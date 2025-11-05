// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inttest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	slogenv "github.com/cbrewster/slog-env"
	"github.com/fatih/color"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
)

type contextkey int

const pgxTraceContextKey contextkey = 1

type ColoredHandler struct {
	mu     sync.Mutex
	w      io.Writer
	opts   slog.HandlerOptions
	attrs  []slog.Attr
	groups []string
}

func NewColoredHandler(w io.Writer, opts *slog.HandlerOptions) *ColoredHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &ColoredHandler{w: w, opts: *opts}
}

func (h *ColoredHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *ColoredHandler) Handle(_ context.Context, r slog.Record) error {
	level := r.Level.String()

	var c *color.Color
	switch r.Level {
	case slog.LevelDebug:
		c = color.New(color.FgGreen)
	case slog.LevelInfo:
		c = color.New(color.FgBlue)
	case slog.LevelWarn:
		c = color.New(color.FgYellow)
	case slog.LevelError:
		c = color.New(color.FgRed)
	default:
		c = color.New(color.FgWhite)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Format time.
	timeStr := r.Time.Format("2006-01-02 15:04:05")

	// Format message with color.
	msg := fmt.Sprintf("%s [%s] %s", timeStr, c.Sprint(level), r.Message)

	// Add attributes.
	var attrStrs []string
	r.Attrs(func(a slog.Attr) bool {
		val := a.Value.Any()
		valStr := fmt.Sprintf("%v", val)
		valStr = strings.ReplaceAll(valStr, "\n", " ")
		valStr = strings.Join(strings.Fields(valStr), " ") // Remove consecutive whitespace
		switch a.Key {
		case "sql":
			attrStrs = append(attrStrs, "\n    sql="+color.GreenString(valStr))
		case "args":
			attrStrs = append(attrStrs, "\n    args="+color.BlueString(valStr))
		default:
			attrStrs = append(attrStrs, fmt.Sprintf("%s=%v", a.Key, valStr))
		}
		return true
	})
	if len(attrStrs) > 0 {
		msg += strings.Join(attrStrs, "")
	}
	_, err := fmt.Fprintln(h.w, msg)
	return err
}

func (h *ColoredHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColoredHandler{
		w:      h.w,
		opts:   h.opts,
		attrs:  append(h.attrs, attrs...),
		groups: h.groups,
	}
}

func (h *ColoredHandler) WithGroup(name string) slog.Handler {
	return &ColoredHandler{
		w:      h.w,
		opts:   h.opts,
		attrs:  h.attrs,
		groups: append(h.groups, name),
	}
}

type LoggingTracer struct {
	logger *slog.Logger
}

// ensure that the LoggingTrace implements the pgx.QueryTracer interface.
var _ pgx.QueryTracer = &LoggingTracer{}

// ensure that the LoggingTrace implements the pgx.CopyFromTracer interface.
var _ pgx.CopyFromTracer = &LoggingTracer{}

// TODO: Implement BatchTracer interface.
// TODO: Implement PrepareTracer interface.
// TODO: Implement ConnectTracer interface.
// TODO: Implement PoolAcquireTracer interface.
// TODO: Implement PoolReleaseTracer interface.

// Stored procedure related regex patterns.
var (
	callStmtRegex   = regexp.MustCompile(`(?i)CALL\s+([^\s(]+)`)
	execStmtRegex   = regexp.MustCompile(`(?i)EXECUTE\s+PROCEDURE\s+([^\s(]+)`)
	selectFuncRegex = regexp.MustCompile(`(?i)SELECT\s+(?:[^\s.,]+\.)?([^\s.,]+)\(`)
)

// TraceContext holds information about a query execution.
type TraceContext struct {
	StartTime     time.Time
	SQL           string
	IsProcedure   bool
	ProcedureName string
}

func NewLoggingTracer() *multitracer.Tracer {
	level := slog.LevelDebug
	handler := NewColoredHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	logger := slog.New(slogenv.NewHandler(handler, slogenv.WithDefaultLevel(level)))
	lgTracer := &LoggingTracer{logger: logger}
	t := &multitracer.Tracer{
		QueryTracers:    []pgx.QueryTracer{lgTracer},
		CopyFromTracers: []pgx.CopyFromTracer{lgTracer},
	}

	return t
}

// identifyStoredProcedure tries to identify if the SQL is a stored procedure call and returns the procedure name.
func identifyStoredProcedure(sql string) (bool, string) {
	// Check for CALL statement (PostgreSQL 11+)
	if match := callStmtRegex.FindStringSubmatch(sql); len(match) > 1 {
		return true, match[1]
	}

	// Check for EXECUTE PROCEDURE statement
	if match := execStmtRegex.FindStringSubmatch(sql); len(match) > 1 {
		return true, match[1]
	}

	// Check for function call via SELECT
	if match := selectFuncRegex.FindStringSubmatch(sql); len(match) > 1 {
		return true, match[1]
	}

	return false, ""
}

func (lt *LoggingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	isProcedure, procedureName := identifyStoredProcedure(data.SQL)

	// Create trace context
	traceCtx := &TraceContext{
		StartTime:     time.Now(),
		SQL:           data.SQL,
		IsProcedure:   isProcedure,
		ProcedureName: procedureName,
	}

	logAttrs := []any{
		"sql", data.SQL,
		"args", fmt.Sprintf("%v", data.Args),
	}

	if isProcedure {
		logAttrs = append(logAttrs, "procedure", procedureName)
		lt.logger.Debug("[PROCEDURE START]", logAttrs...)
	} else {
		lt.logger.Debug("[QUERY START]", logAttrs...)
	}

	// TODO figure out why our context was nil in the trace...
	if ctx == nil {
		ctx = context.Background()
	}
	// Store trace context in the context
	return context.WithValue(ctx, pgxTraceContextKey, traceCtx)
}

func (lt *LoggingTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	// Retrieve trace context if available
	var traceCtx *TraceContext
	if ctx != nil {
		if tc, ok := ctx.Value("pgx_trace_context").(*TraceContext); ok {
			traceCtx = tc
		}
	}

	// Calculate duration if we have start time
	var duration time.Duration
	if traceCtx != nil {
		duration = time.Since(traceCtx.StartTime)
	}

	isProcedure := traceCtx != nil && traceCtx.IsProcedure
	procedureName := ""
	if isProcedure {
		procedureName = traceCtx.ProcedureName
	}

	if data.Err != nil {
		logAttrs := []any{
			"command_tag", data.CommandTag.String(),
			"error", data.Err,
		}

		if duration > 0 {
			logAttrs = append(logAttrs, "duration_ms", duration.Milliseconds())
		}

		if isProcedure {
			logAttrs = append(logAttrs, "procedure", procedureName)
			lt.logger.Error("[PROCEDURE ERROR]", logAttrs...)
		} else {
			lt.logger.Error("[QUERY ERROR]", logAttrs...)
		}
	} else {
		var command string
		switch {
		case data.CommandTag.Insert():
			command = "INSERT"
		case data.CommandTag.Update():
			command = "UPDATE"
		case data.CommandTag.Delete():
			command = "DELETE"
		case data.CommandTag.Select():
			command = "SELECT"
		default:
			command = "UNKNOWN"
			// Try to determine if it's a procedure call
			if isProcedure || strings.HasPrefix(strings.ToUpper(data.CommandTag.String()), "CALL") {
				command = "CALL"
			}
		}

		logAttrs := []any{
			"command", command,
			"rows_affected", data.CommandTag.RowsAffected(),
		}

		if duration > 0 {
			logAttrs = append(logAttrs, "duration_ms", duration.Milliseconds())
		}

		if isProcedure {
			logAttrs = append(logAttrs, "procedure", procedureName)
			lt.logger.Debug("[PROCEDURE SUCCESS]", logAttrs...)
		} else {
			lt.logger.Debug("[QUERY SUCCESS]", logAttrs...)
		}
	}
}

func (lt *LoggingTracer) TraceCopyFromStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromStartData) context.Context {
	lt.logger.Debug("[COPYFROM START]",
		"tablename", data.TableName,
		"columns", fmt.Sprintf("%v", data.ColumnNames),
	)
	if ctx != nil {
		return ctx
	}
	// TODO figure out why our context was nil in the trace...
	return context.Background()
}

func (lt *LoggingTracer) TraceCopyFromEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceCopyFromEndData) {
	if data.Err != nil {
		lt.logger.Error("[COPYFROMQUERY ERROR]",
			"error", data.Err,
		)
	} else {
		lt.logger.Debug("[COPYFROMQUERY SUCCESS]",
			"rows_affected", data.CommandTag.RowsAffected(),
		)
	}
}

// Implement other Tracer methods as needed (e.g., TraceBatchStart, TraceBatchEnd, etc.)

func NewLoggingConn(config *pgxpool.Config) (*pgxpool.Pool, error) {
	tracer := NewLoggingTracer()
	config.ConnConfig.Tracer = tracer
	return pgxpool.NewWithConfig(context.Background(), config)
}
