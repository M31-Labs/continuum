package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

type EventHandler func(context.Context, event.Event) error

const DefaultSourceLoopBufferSize = 64

type SourceLoopOptions struct {
	BufferSize int
	Health     *SourceHealthStore
}

// RunSource is Continuum's generic event ingestion loop. Source implementations
// may be backed by Horizon, OS fixtures, tests, or future adapters, but the
// runtime only depends on the narrow capability.Source interface.
func RunSource(ctx context.Context, src capability.Source, handler EventHandler) error {
	return RunSourceWithOptions(ctx, src, handler, SourceLoopOptions{BufferSize: DefaultSourceLoopBufferSize})
}

func RunSourceWithHealth(ctx context.Context, src capability.Source, handler EventHandler, health *SourceHealthStore) error {
	return RunSourceWithOptions(ctx, src, handler, SourceLoopOptions{BufferSize: DefaultSourceLoopBufferSize, Health: health})
}

func RunSourceWithOptions(ctx context.Context, src capability.Source, handler EventHandler, opts SourceLoopOptions) error {
	if src == nil {
		return fmt.Errorf("source is required")
	}
	if handler == nil {
		return fmt.Errorf("event handler is required")
	}
	if opts.BufferSize < 0 {
		return fmt.Errorf("source buffer size must be non-negative")
	}
	name := strings.TrimSpace(src.Name())
	if name == "" {
		return fmt.Errorf("source name is required")
	}
	health := opts.Health
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	queue := make(chan event.Event, opts.BufferSize)
	var (
		mu      sync.Mutex
		runErr  error
		errOnce sync.Once
	)
	setErr := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			mu.Lock()
			runErr = err
			mu.Unlock()
			cancel()
		})
	}
	getErr := func() error {
		mu.Lock()
		defer mu.Unlock()
		return runErr
	}

	if health != nil {
		health.MarkStarting(name, opts.BufferSize)
		health.MarkRunning(name)
	}
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		for {
			select {
			case evt, ok := <-queue:
				if !ok {
					return
				}
				if err := handler(runCtx, evt); err != nil {
					setErr(err)
					return
				}
			case <-runCtx.Done():
				return
			}
		}
	}()

	sourceErr := src.Start(runCtx, func(emitCtx context.Context, evt event.Event) error {
		if err := getErr(); err != nil {
			return err
		}
		select {
		case queue <- evt:
			if health != nil {
				health.RecordEvent(name)
			}
			return nil
		default:
			if health != nil {
				health.RecordBackpressure(name)
			}
		}
		select {
		case queue <- evt:
			if health != nil {
				health.RecordEvent(name)
			}
			return nil
		case <-runCtx.Done():
			if err := getErr(); err != nil {
				return err
			}
			return runCtx.Err()
		case <-emitCtx.Done():
			if err := getErr(); err != nil {
				return err
			}
			return emitCtx.Err()
		}
	})
	close(queue)
	<-handlerDone
	handlerErr := getErr()
	err := firstSourceLoopError(sourceErr, handlerErr)
	if err != nil {
		if health != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				health.MarkStopped(name)
			} else {
				health.MarkFailed(name, err)
			}
		}
		return err
	}
	if health != nil {
		health.MarkStopped(name)
	}
	return nil
}

func firstSourceLoopError(sourceErr, handlerErr error) error {
	if handlerErr != nil && (sourceErr == nil || errors.Is(sourceErr, context.Canceled)) {
		return handlerErr
	}
	if sourceErr != nil {
		return sourceErr
	}
	return handlerErr
}
