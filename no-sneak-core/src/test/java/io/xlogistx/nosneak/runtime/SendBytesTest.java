package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.net.IPAddress;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** Pins the {@code send} codecs: which prefixes decode, and that only text is templated. */
public class SendBytesTest {

    private static ProbeContext context(String sendState) {
        String json = "{\"name\":\"codec\",\"service\":\"x\",\"ports\":[2525],\"start\":\"connect\",\"states\":{"
                + "\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"s\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
                + "\"s\":" + sendState + ","
                + "\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}";
        ProbeDefinition def = ProbeDefinitionLoader.parse(json, "codec");
        ScriptedTransport tx = new ScriptedTransport();
        ProbeContext ctx = tx.newContext(new ManualScheduler(), new IPAddress("10.1.2.3", 2525), def, 2);
        ctx.start(); // sets the current port so {probe.port} has a value
        return ctx;
    }

    private static byte[] resolve(String sendState) {
        ProbeContext ctx = context(sendState);
        return ctx.resolveSendBytes(ctx.result() == null ? null
                : ProbeDefinitionLoader.parse("{\"name\":\"n\",\"service\":\"x\",\"start\":\"s\",\"states\":{\"s\":"
                        + sendState + ",\"done\":{\"action\":\"done\"}}}", "n").state("s"));
    }

    @Test
    public void hexPrefixDecodesBytesAndIsNeverTemplated() {
        byte[] b = resolve("{\"action\":\"send\",\"data\":\"hex:00ff7b70726f62652e706f72747d\",\"on\":{\"sent\":\"done\"}}");
        assertArrayEquals(new byte[]{0, (byte) 0xff, '{', 'p', 'r', 'o', 'b', 'e', '.', 'p', 'o', 'r', 't', '}'}, b);
    }

    @Test
    public void base64PrefixDecodes() {
        byte[] b = resolve("{\"action\":\"send\",\"data\":\"base64:aGVsbG8=\",\"on\":{\"sent\":\"done\"}}");
        assertEquals("hello", new String(b, StandardCharsets.UTF_8));
    }

    @Test
    public void textPrefixIsTemplated() {
        byte[] b = resolve("{\"action\":\"send\",\"data\":\"text:HELO {probe.hostname}:{probe.port}\\r\\n\",\"on\":{\"sent\":\"done\"}}");
        assertEquals("HELO 10.1.2.3:2525\r\n", new String(b, StandardCharsets.UTF_8));
    }

    @Test
    public void bareDataIsTextAndTemplated() {
        byte[] b = resolve("{\"action\":\"send\",\"data\":\"Host: {probe.hostname}\",\"on\":{\"sent\":\"done\"}}");
        assertEquals("Host: 10.1.2.3", new String(b, StandardCharsets.UTF_8));
    }

    @Test
    public void payloadIsTheTemplatedFallbackWhenDataIsAbsent() {
        byte[] b = resolve("{\"action\":\"send\",\"payload\":\"EHLO {probe.hostname}\\r\\n\",\"on\":{\"sent\":\"done\"}}");
        assertEquals("EHLO 10.1.2.3\r\n", new String(b, StandardCharsets.UTF_8));
    }

    @Test
    public void dataWinsOverPayloadWhenBothArePresent() {
        byte[] b = resolve("{\"action\":\"send\",\"data\":\"text:A\",\"payload\":\"B\",\"on\":{\"sent\":\"done\"}}");
        assertEquals("A", new String(b, StandardCharsets.UTF_8));
    }

    @Test
    public void theSendActionWritesExactlyThoseBytesToTheConnection() {
        ScriptedTransport tx = new ScriptedTransport();
        String json = "{\"name\":\"w\",\"service\":\"x\",\"ports\":[1],\"start\":\"connect\",\"states\":{"
                + "\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"s\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
                + "\"s\":{\"action\":\"send\",\"data\":\"hex:0102\",\"on\":{\"sent\":\"done\",\"error\":\"fail\"}},"
                + "\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}";
        ProbeContext ctx = tx.newContext(new ManualScheduler(), new IPAddress("127.0.0.1", 1),
                ProbeDefinitionLoader.parse(json, "w"), 2);
        ctx.start();
        ScriptedTransport.connected(tx.last());
        assertEquals(1, tx.last().written.size());
        assertArrayEquals(new byte[]{1, 2}, tx.last().written.get(0));
        assertEquals(1, tx.delivered.size());
    }
}
