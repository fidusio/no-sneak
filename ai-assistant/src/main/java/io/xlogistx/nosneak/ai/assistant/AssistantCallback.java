package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIMessage;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.zoxweb.shared.task.ConsumerCallback;
import org.zoxweb.shared.util.NVGenericMap;

import javax.swing.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class AssistantCallback implements ConsumerCallback<NVGenericMap> {
    private final AssistantContext context;
    private final AIChat chat;
    private final AIMessage message;
    private final Consumer<AIResponse> onResponse;
    private final Consumer<Throwable> onError;
    private final long start = System.nanoTime();

    public AssistantCallback(AssistantContext context, AIChat chat, AIMessage message,
                             Consumer<AIResponse> onResponse, Consumer<Throwable> onError) {
        this.context = context;
        this.chat = chat;
        this.message = message;
        this.onResponse = onResponse;
        this.onError = onError;
    }

    @Override
    public void accept(NVGenericMap payload) {
        AIResponse response;
        try {
            response = new AIResponse();
            response.setContent(AssistantMDDecoder.SINGLETON.decode(payload));
            response.setModel(message.getAIRequest().getModel());
            response.setTokens(AssistantMDDecoder.tokens(payload));
            response.setLatency(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
            message.setAIResponse(response);
        } catch (Exception e) {
            exception(e);
            return;
        }
        Exception persistError = null;
        try {
            context.saveChat(chat);
        } catch (Exception e) {
            persistError = e;
        }
        final Exception saveError = persistError;
        SwingUtilities.invokeLater(() -> {
            onResponse.accept(response);
            if (saveError != null)
                JOptionPane.showMessageDialog(null,
                        "The reply was received but saving the chat failed: " + saveError.getMessage(),
                        "Save", JOptionPane.WARNING_MESSAGE);
        });
    }

    @Override
    public void exception(Throwable e) {
        SwingUtilities.invokeLater(() -> {
            chat.getMessages().remove(message);
            onError.accept(e);
        });
    }
}
