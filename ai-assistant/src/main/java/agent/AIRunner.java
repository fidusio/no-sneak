package agent;

import agent.model.AIRequest;
import agent.model.AIResponse;

import java.util.List;
import java.util.function.Function;

/**
 * Runs one request against several models at once and collects every outcome — the "ask everyone the
 * same question, compare the answers" layer that sits above {@link AIProvider}. One model failing
 * doesn't sink the others: each result is a {@link RunResult.Success} or {@link RunResult.Failure}.
 */
public interface AIRunner {

    /**
     * Runs the request against all targets and returns one result per target.
     */
    List<RunResult> run(Run run);

    /**
     * Same fan-out, but streams each target's answer to the listener {@code listeners} returns for it.
     */
    void runStreaming(Run run, Function<RunTarget, AIStreamListener> listeners, AICancelToken token);

    /**
     * One credential paired with one model to run against.
     */
    record RunTarget(AICredential credential, String model) {
    }

    /**
     * One request sent to every target (each gets identical prompt/skills/messages).
     */
    record Run(List<RunTarget> targets, AIRequest request) {
    }

    /**
     * The outcome for one target. Sealed so the switch rendering your answer columns can't forget the
     * error branch.
     */
    sealed interface RunResult {
        RunTarget target();

        /**
         * The target answered.
         */
        record Success(RunTarget target, AIResponse response) implements RunResult {
        }

        /**
         * The target failed; the error is carried, not thrown, so other targets survive.
         */
        record Failure(RunTarget target, AIException error) implements RunResult {
        }
    }
}
