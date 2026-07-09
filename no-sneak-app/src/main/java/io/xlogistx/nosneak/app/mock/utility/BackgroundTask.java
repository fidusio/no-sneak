package io.xlogistx.nosneak.app.mock.utility;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * Runs blocking work (auth calls, crypto, I/O) off the Swing EDT and delivers the
 * result back on the EDT, so the UI never freezes. Optionally disables a control while
 * the task is in flight to block double-submits.
 */
public final class BackgroundTask {
    private BackgroundTask() {
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    /**
     * Generic form: run {@code work} on a background thread, then hand its result to
     * {@code onDone} on the EDT. If {@code work} throws, an error dialog is shown and
     * {@code onDone} is not called.
     *
     * @param owner     component the dialog is parented to (may be null)
     * @param toDisable control disabled while running, re-enabled after (may be null)
     * @param work      the blocking task (runs off the EDT — do no Swing here)
     * @param onDone    receives the result on the EDT
     */
    public static <T> void run(Component owner, JComponent toDisable,
                               Callable<T> work, Consumer<T> onDone) {
        if (toDisable != null) toDisable.setEnabled(false);

        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return work.call();
            }

            @Override
            protected void done() {
                if (toDisable != null) toDisable.setEnabled(true);
                T result;
                try {
                    result = get();
                } catch (InterruptedException | ExecutionException ex) {
                    Throwable cause = (ex instanceof ExecutionException && ex.getCause() != null)
                            ? ex.getCause() : ex;
                    String msg = (cause instanceof SecurityException)
                            ? cause.getMessage()
                            : "Unexpected error: " + cause.getMessage();
                    JOptionPane.showMessageDialog(owner, msg, "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                onDone.accept(result);
            }
        }.execute();
    }

    /**
     * Convenience for the exception convention: run {@code work} off the EDT; if it throws,
     * {@link #run}'s handler shows the error dialog (a {@link SecurityException} message as-is,
     * anything else as an unexpected error) and {@code onSuccess} is skipped. On success,
     * {@code onSuccess} (may be null) runs on the EDT.
     */
    public static void runCatching(Component owner, JComponent toDisable,
                                   ThrowingRunnable work, Runnable onSuccess) {
        run(owner, toDisable, () -> {
            work.run();
            return null;
        }, _ -> {
            if (onSuccess != null) onSuccess.run();
        });
    }
}
