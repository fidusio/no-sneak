package io.xlogistx.nosneak.ai.assistant;

import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.GetNameDescriptionDisplay;
import org.zoxweb.shared.util.GetNameDescriptionDisplayImpl;

/**
 * The assistant's UI descriptors (the maintainer's rule of 2026-11-01, the twin of the app's
 * {@code NSAppUtil}): every GUI component or panel this module builds has a constant in one of
 * the enums here, implementing zoxweb's {@link GetName} (the AWT component name, dotted and
 * stable), {@link GetDisplayName} (the text it shows: a button's or label's text, a field's
 * placeholder, a column header, a page title) and {@link GetDescription} (its tooltip). The
 * panels render through those three methods and carry no literal strings of their own;
 * gui-audio's {@code GUIUtil.applyProp(component, ref)} is the one place that maps them onto a
 * component. Each enum wraps a {@link GetNameDescriptionDisplayImpl}, whose constructor takes
 * {@code (name, description, displayName)}; the enum constructors take
 * {@code (name, displayName, description)}.
 */
public class AIAssistantUtil {
    private AIAssistantUtil() {
    }

    /** The assistant's pages (moved here from {@code AssistantPanel.Page}, 2026-11-01). {@code QUEUE} is a stub the host's navigation does not offer. The display name is the page title, the same words as the host sidebar's {@code Screen}; the description one line on what the page is for. */
    public enum Page implements GetNameDescriptionDisplay {
        CHAT("assistant.page.chat", "Chat", "Your chats with the assistant: open one, or start a new one"),
        QUEUE("assistant.page.queue", "Job Queue", "Requests waiting for, or receiving, a reply"),
        SKILLS("assistant.page.skills", "Skills", "Instructions the assistant carries into a chat"),
        PROVIDERS("assistant.page.providers", "Providers", "Which of your API keys the assistant may use, and their models"),
        CAPTURE("assistant.page.capture", "Capture", "Screen areas shot at once, kept for the chat");

        private final GetNameDescriptionDisplay gndd;

        Page(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Skills page (2026-11-01): the list card, its bar and buttons, and the dialog titles of the page. The page title is {@link Page#SKILLS}. */
    public enum SkillsPage implements GetNameDescriptionDisplay {
        PAGE("skills", "", null),
        SUBTITLE("skills.subtitle", "Instructions the assistant can carry into a chat: an md skill goes with the message, a prompt skill is pasted into the composer.", null),
        NEW_SKILL("skills.new", "New skill", "Name it, pick what it is, and write the instructions in markdown"),
        SEARCH("skills.search", "Search by name, type or description", "Filters the skills by name, type or description"),
        COUNT("skills.count", "", "How many skills are listed"),
        COUNT_EMPTY("skills.count.empty", "No skills yet", null),
        TABLE("skills.table", "", "Your skills; select one to edit or delete it, double-click to edit"),
        EDIT("skills.edit", "Edit", "Change the selected skill"),
        DELETE("skills.delete", "Delete", "Delete the selected skill"),
        DELETE_DIALOG("skills.delete.dialog", "Delete skill", null),
        NAME_DIALOG("skills.name.dialog", "Skill", null),
        UNSAVED_DIALOG("skills.unsaved.dialog", "Unsaved skill", null),
        SAVE_AS_DIALOG("skills.saveAs.dialog", "Save as", null),
        NOT_VALID_DIALOG("skills.notValid.dialog", "Not a valid", null);

        private final GetNameDescriptionDisplay gndd;

        SkillsPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The skill editor (2026-11-01): the one markdown editor's title, field labels, type row, Save / Create texts, and the pages that frame it. */
    public enum SkillEditor implements GetNameDescriptionDisplay {
        EDITOR("skillEditor", "", null),
        TITLE("skillEditor.title", "Skill instructions", null),
        NAME("skillEditor.name", "Name", null),
        DESCRIPTION("skillEditor.description", "Description", null),
        TYPE("skillEditor.type", "Save as", null),
        CREATE("skillEditor.create", "Create", null),
        SAVE("skillEditor.save", "Save", null),
        PAGE_NEW("skillEditor.page.new", "New skill", "Name it, pick what it is, and write the instructions in markdown. Save as sends the text elsewhere instead."),
        PAGE_EDIT("skillEditor.page.edit", "Edit skill", "Change the name, type, description or instructions. Cancel discards the edits."),
        PAGE_FROM_RESPONSE("skillEditor.page.fromResponse", "New skill", "The assistant's reply, ready to keep as a skill: name it and save.");

        private final GetNameDescriptionDisplay gndd;

        SkillEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the Skills table, in order; {@code SkillsTableModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum SkillsColumn implements GetNameDescriptionDisplay {
        NAME("skills.col.name", "Skill", "The skill's name"),
        TYPE("skills.col.type", "Type", "md skill goes with the message, prompt skill is pasted into the composer"),
        DESCRIPTION("skills.col.description", "Description", null),
        UPDATED("skills.col.updated", "Updated", "The last change");

        private final GetNameDescriptionDisplay gndd;

        SkillsColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The list of chats, the Chat page's list card (2026-11-01): its bar, buttons and dialog titles. The page title is {@link Page#CHAT}. */
    public enum ChatHistoryPage implements GetNameDescriptionDisplay {
        PAGE("chatHistory", "", null),
        SUBTITLE("chatHistory.subtitle", "Every chat you had with the assistant, kept in this store under your account only. Open one to continue it, or start a new one.", null),
        NEW_CHAT("chatHistory.new", "New chat", "Name a chat and pick the provider and model it will talk to"),
        SEARCH("chatHistory.search", "Search by title, provider or model", "Filters the chats by title, provider or model"),
        COUNT("chatHistory.count", "", "How many chats are listed"),
        COUNT_EMPTY("chatHistory.count.empty", "No chats yet", null),
        TABLE("chatHistory.table", "", "Your chats, newest update first; double-click opens one"),
        OPEN("chatHistory.open", "Open", "Continue the selected chat"),
        EDIT("chatHistory.edit", "Edit", "Rename the selected chat, or change its provider and model"),
        DELETE("chatHistory.delete", "Delete", "Delete the selected chat"),
        DELETE_DIALOG("chatHistory.delete.dialog", "Delete chat", null);

        private final GetNameDescriptionDisplay gndd;

        ChatHistoryPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The New chat and Edit chat forms (2026-11-01): their page titles and descriptions, the three rows, their fields, and the buttons. */
    public enum ChatEditor implements GetNameDescriptionDisplay {
        EDIT_PAGE("chatEditor.edit", "Edit chat", "Rename the chat, or change the provider and model it talks to."),
        NEW_PAGE("chatEditor.new", "New chat", "Name it and pick the provider and model it will talk to."),
        NAME("chatEditor.name", "Name", null),
        PROVIDER("chatEditor.provider", "Provider", null),
        MODEL("chatEditor.model", "Model", null),
        EDIT_NAME_FIELD("chatEditor.edit.name.field", "", null),
        EDIT_PROVIDER_FIELD("chatEditor.edit.provider.field", "", null),
        EDIT_MODEL_FIELD("chatEditor.edit.model.field", "", null),
        NEW_NAME_FIELD("chatEditor.new.name.field", "", null),
        NEW_PROVIDER_FIELD("chatEditor.new.provider.field", "", null),
        NEW_MODEL_FIELD("chatEditor.new.model.field", "", null),
        SAVE("chatEditor.save", "Save", null),
        CREATE("chatEditor.create", "Create", null),
        CANCEL("chatEditor.cancel", "Cancel", "Back to the list"),
        MISSING_DIALOG("chatEditor.missing.dialog", "Missing selection", null);

        private final GetNameDescriptionDisplay gndd;

        ChatEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the chat list, in order; {@code ChatHistoryModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum ChatHistoryColumn implements GetNameDescriptionDisplay {
        TITLE("chatHistory.col.title", "Chat", "The chat's title"),
        PROVIDER("chatHistory.col.provider", "Provider", "The assistant the chat talks to"),
        MODEL("chatHistory.col.model", "Model", "The model the chat talks to"),
        MESSAGES("chatHistory.col.messages", "Messages", "How many turns the chat holds"),
        CREATED("chatHistory.col.created", "Created", null),
        UPDATED("chatHistory.col.updated", "Updated", null);

        private final GetNameDescriptionDisplay gndd;

        ChatHistoryColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Capture page (2026-10-26 layout): head actions, the Areas and Captures toolbar-over-table columns, the preview page and the dialog titles. {@code HIDE_WINDOW}'s name is the box's component name, {@code CapturePanel.HIDE_WINDOW}. */
    public enum CapturePage implements GetNameDescriptionDisplay {
        PAGE("capture.page", "", null),
        SUBTITLE("capture.subtitle", "Draw areas on the screen and shoot them all at once. Areas last the session; captures are kept under your account.", null),
        DEFINE_AREA("capture.defineArea", "Define area", "Drag out a region of the screen as a reusable capture area"),
        CAPTURE("capture.capture", "Capture", "Capture an image of every area"),
        HIDE_WINDOW("hide-window", "Hide window", "Hide this window while an area is drawn or shot; untick to draw over and capture the application itself"),
        CAPTURE_DIALOG("capture.dialog", "Capture", null),
        AREAS("capture.areas", "Areas", null),
        AREAS_NOTE("capture.areas.note", "", null),
        AREAS_EMPTY("capture.areas.empty", "No areas yet", null),
        AREAS_TABLE("capture.areas.table", "", null),
        AREA_RENAME("capture.areas.rename", "Rename", null),
        AREA_REDRAW("capture.areas.redraw", "Redraw", "Drag the region again, keeping the name"),
        AREA_REMOVE("capture.areas.remove", "Remove", null),
        CAPTURES("capture.captures", "Captures", null),
        CAPTURES_NOTE("capture.captures.note", "", null),
        CAPTURES_EMPTY("capture.captures.empty", "No captures yet", null),
        CAPTURES_TABLE("capture.captures.table", "", null),
        OPEN("capture.captures.open", "Open", null),
        SEND("capture.captures.send", "Send to chat", null),
        RENAME("capture.captures.rename", "Rename", null),
        DELETE("capture.captures.delete", "Delete", null),
        DELETE_ALL("capture.captures.deleteAll", "Delete all", "Delete every saved capture"),
        DELETE_DIALOG("capture.captures.delete.dialog", "Delete capture", null),
        DELETE_ALL_DIALOG("capture.captures.deleteAll.dialog", "Delete all captures", null),
        PREVIEW("capture.preview", "", null),
        PREVIEW_BACK("capture.preview.back", "Back", null),
        PREVIEW_SEND("capture.preview.send", "Send to chat", null),
        PREVIEW_PICTURE("capture.preview.picture", "", null);

        private final GetNameDescriptionDisplay gndd;

        CapturePage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the Captures table, in order; {@code CaptureTableModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum CaptureColumn implements GetNameDescriptionDisplay {
        THUMB("capture.col.thumb", "", "The capture's thumbnail"),
        NAME("capture.col.name", "Capture", "The capture's name"),
        AREA("capture.col.area", "Area", "The capture area it was shot from"),
        SIZE("capture.col.size", "Size", "Width x height in pixels"),
        BYTES("capture.col.bytes", "Bytes", "The stored image's size"),
        TAKEN("capture.col.taken", "Taken", "When it was shot");

        private final GetNameDescriptionDisplay gndd;

        CaptureColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the Areas table, in order; {@code CaptureAreaModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum CaptureAreaColumn implements GetNameDescriptionDisplay {
        NAME("captureArea.col.name", "Area", "The area's name, edited in place"),
        DISPLAY("captureArea.col.display", "Display", "The screen it was drawn on"),
        REGION("captureArea.col.region", "Region", "Width x height at x,y");

        private final GetNameDescriptionDisplay gndd;

        CaptureAreaColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Job Queue stub page: its list section's add button and search placeholder. */
    public enum JobQueuePage implements GetNameDescriptionDisplay {
        PAGE("jobQueue.page", "", null),
        ADD_JOB("jobQueue.add", "+ Add Job", null),
        SEARCH("jobQueue.search", "search", null);

        private final GetNameDescriptionDisplay gndd;

        JobQueuePage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The conversation page of the Chat page (2026-11-01): its head actions, the provider and model row, the transcript and its dialog titles. */
    public enum ChatPage implements GetNameDescriptionDisplay {
        PAGE("chat.page", "", "The open conversation: transcript over the composer"),
        TRANSCRIPT("chat.transcript", "", null),
        ALL_CHATS("chat.allChats", "All chats", "Back to the list of chats"),
        EDIT("chat.edit", "Edit", "Rename this chat, or change its provider and model"),
        CHAT_AS_PDF("chat.pdf", "Chat as PDF", "Show the whole chat as a PDF"),
        PDF_DIALOG("chat.pdf.dialog", "Chat as PDF", null),
        NEW_CHAT("chat.new", "New chat", "Create a new chat"),
        PROVIDER("chat.provider", "Provider", null),
        PROVIDER_SELECTOR("chat.provider.selector", "", "The assistant the next message goes to. Switching keeps this chat and its transcript; the model list follows"),
        MODEL("chat.model", "Model", null),
        MODEL_SELECTOR("chat.model.selector", "", "The model the next message goes to. Type to narrow the list: gpt-4*, o3, !*preview*  "
                + "(bare words match anywhere, ! excludes, blank hides non-chat models); a name the list does not offer is kept as typed"),
        SEND_HISTORY("chat.sendHistory", "Send history", "Checked: each request carries the whole conversation. Unchecked: only the new message is sent."),
        AUTO_COPY_CODE("chat.autoCopyCode", "Auto-copy code", "Checked: the code blocks of every new reply are copied to the clipboard as it arrives."),
        SEND_DIALOG("chat.send.dialog", "Send", null),
        NOT_VALID_DIALOG("chat.saveAs.invalid.dialog", "Not a valid", "Followed by the save target's label");

        private final GetNameDescriptionDisplay gndd;

        ChatPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The composer bar (2026-11-01): the input, Send, the clear X, the + button and its popup's sections, rows and choosers. */
    public enum Composer implements GetNameDescriptionDisplay {
        INPUT("composer.input", "", null),
        SEND("composer.send", "Send", null),
        CLEAR("composer.clear", "", "Clear the prompt (what is attached stays)"),
        ATTACH("composer.attach", "", "Attach skills, sources or capture areas to the next message"),
        ATTACHED("composer.attached", "Attached to the next message:", "The + button's tooltip once something is attached, followed by the names"),
        SECTION_SKILLS("composer.section.skills", "Skills for this message", null),
        EMPTY_SKILLS("composer.skills.empty", "No skills yet", null),
        SECTION_BUILT_IN("composer.section.builtIn", "Built-in skills", null),
        SECTION_SOURCES("composer.section.sources", "Sources for this message", null),
        SECTION_CAPTURE("composer.section.capture", "Capture", null),
        EMPTY_AREAS("composer.areas.empty", "No capture areas yet", null),
        ALL_AREAS("composer.areas.all", "All areas", "Send every capture area with the next message"),
        REMOVE_AREA("composer.areas.remove", "", "Remove this capture area"),
        DROP_SOURCE("composer.source.drop", "", "Drop this from the next message"),
        INSERT_SKILL("composer.skill.insert", "", "Insert into the message"),
        ATTACH_FILE("composer.attachFile", "Attach file", "Send the contents of a text file with this message"),
        ADD_URL("composer.addUrl", "Add URL", "Fetch a page and send its text with this message"),
        ATTACH_IMAGE("composer.attachImage", "Attach image", "Pick one or more png or jpeg files to send with this message"),
        IMAGE_FILTER("composer.attachImage.filter", "Images", null),
        CAPTURE_AREA("composer.captureArea", "Capture area...", "Drag out a region and add it to the capture areas");

        private final GetNameDescriptionDisplay gndd;

        Composer(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** A chat bubble's action row (2026-11-01, {@code AssistantUtil.chatBubble}): the detail line, Save as skill, Save as &lt;target&gt;, reuse, copy and PDF. */
    public enum ChatBubble implements GetNameDescriptionDisplay {
        DETAIL("bubble.detail", "", null),
        SAVE_AS_SKILL("bubble.saveAsSkill", "Save as skill", "Open the skill editor seeded with this response"),
        SAVE_AS("bubble.saveAs", "Save as", "Save this response as a"),
        REUSE("bubble.reuse", "", "Put this prompt back in the composer to send it again"),
        COPY("bubble.copy", "", "Copy the response text"),
        PDF("bubble.pdf", "", "Show this response as a PDF"),
        PDF_DIALOG("bubble.pdf.dialog", "Response as PDF", null);

        private final GetNameDescriptionDisplay gndd;

        ChatBubble(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Providers page (2026-11-01): the table page (title from {@link Page#PROVIDERS}) and the key picker page behind Add provider. */
    public enum ProvidersPage implements GetNameDescriptionDisplay {
        PAGE("providers", "", null),
        SUBTITLE("providers.subtitle", "Keys come from your NoSneak credentials. Adding one here lets the assistant use it and discover its models.", null),
        ADD("providers.add", "Add provider", null),
        SEARCH("providers.search", "Search by label, type, endpoint or model", null),
        COUNT("providers.count", "", null),
        COUNT_EMPTY("providers.count.empty", "No providers yet", null),
        EDIT("providers.edit", "Edit", null),
        REMOVE("providers.remove", "Remove", "Remove the provider; the key stays in your NoSneak credentials"),
        TABLE("providers.table", "", null),
        NEVER_SYNCED("providers.neverSynced", "never synced", null),
        REMOVE_DIALOG("providers.remove.dialog", "Remove provider", null),
        ERROR_DIALOG("providers.error.dialog", "Provider Error", null),
        MISSING_DIALOG("providers.missing.dialog", "Missing information", null),
        PICKER("providers.picker", "Add a provider", "Pick a credential from your NoSneak key store, or add a brand-new key. One key can back several providers."),
        PICKER_BACK("providers.picker.back", "Back", null),
        PICKER_NEW_KEY("providers.picker.newKey", "New key", null),
        PICKER_COUNT("providers.picker.count", "", null),
        PICKER_COUNT_EMPTY("providers.picker.count.empty", "No keys yet", null),
        PICKER_USE("providers.picker.use", "Use this key", null),
        PICKER_TABLE("providers.picker.table", "", null),
        PICKER_UNSAVED_DIALOG("providers.picker.unsaved.dialog", "Add provider", null);

        private final GetNameDescriptionDisplay gndd;

        ProvidersPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The New provider key page (2026-11-01): a credential NoSneak does not have yet, created through the source before the provider form opens. */
    public enum ProviderKeyEditor implements GetNameDescriptionDisplay {
        PAGE("providerKey", "New provider key", "A key NoSneak does not have yet. It becomes an ordinary credential of yours, visible on the API Keys page."),
        LABEL("providerKey.label", "Label*", null),
        LABEL_FIELD("providerKey.label.field", "e.g. Claude prod", null),
        PROVIDER("providerKey.provider", "Provider*", null),
        PROVIDER_FIELD("providerKey.provider.field", "", null),
        API_KEY("providerKey.apiKey", "API key*", null),
        API_KEY_FIELD("providerKey.apiKey.field", "Your API key", null),
        BASE_URL("providerKey.baseUrl", "Base URL", null),
        BASE_URL_FIELD("providerKey.baseUrl.field", "Optional — provider default when empty", null),
        CREATE("providerKey.create", "Add to assistant", null),
        CANCEL("providerKey.cancel", "Cancel", null);

        private final GetNameDescriptionDisplay gndd;

        ProviderKeyEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The provider form (2026-11-01): one card framed as an Add provider or Edit provider page on every open; the Default model row is hidden on the add path. */
    public enum ProviderForm implements GetNameDescriptionDisplay {
        FORM("providerForm", "", null),
        ADD_PAGE("providerForm.add", "Add provider", "Name it and confirm the service and endpoint; the default model can be picked once its models are discovered."),
        EDIT_PAGE("providerForm.edit", "Edit provider", "Change what the assistant calls it, which service it talks to, its endpoint and the model it starts with."),
        KEY("providerForm.key", "Key", null),
        KEY_VALUE("providerForm.key.value", "", null),
        LABEL("providerForm.label", "Label*", null),
        LABEL_FIELD("providerForm.label.field", "e.g. Claude prod", null),
        TYPE("providerForm.type", "Provider*", null),
        TYPE_FIELD("providerForm.type.field", "", null),
        BASE_URL("providerForm.baseUrl", "Base URL", null),
        BASE_URL_FIELD("providerForm.baseUrl.field", "Optional — provider default when empty", null),
        MODEL("providerForm.model", "Default model", null),
        MODEL_FIELD("providerForm.model.field", "", null),
        SAVE("providerForm.save", "Save", null),
        SAVE_ADD("providerForm.save.add", "Add to assistant", null),
        CANCEL("providerForm.cancel", "Cancel", null);

        private final GetNameDescriptionDisplay gndd;

        ProviderForm(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the Providers table, in order; {@code ProvidersTableModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum ProvidersColumn implements GetNameDescriptionDisplay {
        NAME("providers.col.name", "Provider", "The provider's label"),
        TYPE("providers.col.type", "Type", "The service it talks to"),
        ENDPOINT("providers.col.endpoint", "Endpoint", "Its base URL"),
        MODEL("providers.col.model", "Default model", "The model a new chat starts with"),
        MODELS("providers.col.models", "Models", "How many models discovery found"),
        SYNCED("providers.col.synced", "Last sync", "When its models were last discovered");

        private final GetNameDescriptionDisplay gndd;

        ProvidersColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the key picker's table, in order; {@code ProviderKeysTableModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum ProviderKeysColumn implements GetNameDescriptionDisplay {
        NAME("providerKeys.col.name", "Key", "The credential's name"),
        PROVIDER("providerKeys.col.provider", "Provider", "The provider type it was stored with"),
        ENDPOINT("providerKeys.col.endpoint", "Endpoint", "Its base URL"),
        USED("providerKeys.col.used", "Used by", "How many live providers borrow it");

        private final GetNameDescriptionDisplay gndd;

        ProviderKeysColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The assistant's host panel itself: the card stack the pages live in, mounted by the application under its sidebar. */
    public enum AssistantShell implements GetNameDescriptionDisplay {
        PANEL("assistant", "Assistant", "The assistant's pages: chat, capture, skills, providers");

        private final GetNameDescriptionDisplay gndd;

        AssistantShell(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    // ---- enums are added above this line; one per panel or feature ----
}
