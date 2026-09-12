package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.runtime.ManualScheduler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;
import org.xbill.DNS.Section;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The PTR lookup's wire shape, reply parsing and exactly-once completion, driven with no
 * socket: replies are built by hand with dnsjava and fed through the ingress hook the
 * selector would call; the deadline is fired by hand on a {@link ManualScheduler}.
 */
public class ReverseDnsCallbackTest {

    private ManualScheduler clock;
    private final List<ReverseDnsCallback.Result> results = new ArrayList<>();

    @BeforeEach
    public void fresh() {
        clock = new ManualScheduler();
        results.clear();
    }

    private ReverseDnsCallback lookup(String ip) throws Exception {
        return new ReverseDnsCallback(clock, InetAddress.getByName(ip),
                new InetSocketAddress(InetAddress.getLoopbackAddress(), ReverseDnsCallback.DNS_PORT),
                ReverseDnsCallback.DEFAULT_TIMEOUT_MS, results::add);
    }

    /** A resolver's answer to {@code cb}'s question: same question, given id, rcode, and an optional PTR. */
    private static byte[] reply(ReverseDnsCallback cb, int id, int rcode, String ptrTarget) throws Exception {
        Record question = new Message(cb.queryWire()).getQuestion();
        Message r = new Message(id);
        r.getHeader().setFlag(Flags.QR);
        r.getHeader().setRcode(rcode);
        r.addRecord(question, Section.QUESTION);
        if (ptrTarget != null) {
            r.addRecord(new PTRRecord(question.getName(), DClass.IN, 300, Name.fromString(ptrTarget)), Section.ANSWER);
        }
        return r.toWire();
    }

    @Test
    public void theQueryAsksForThePtrOfTheReverseZone() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        Message q = new Message(cb.queryWire());
        assertEquals(cb.queryId(), q.getHeader().getID());
        assertTrue(q.getHeader().getFlag(Flags.RD), "recursion desired, like any stub resolver");
        assertEquals("1.0.0.10.in-addr.arpa.", q.getQuestion().getName().toString());
        assertEquals(Type.PTR, q.getQuestion().getType());
        assertEquals(DClass.IN, q.getQuestion().getDClass());

        Message v6 = new Message(lookup("::1").queryWire());
        assertTrue(v6.getQuestion().getName().toString().endsWith(".ip6.arpa."), v6.getQuestion().getName().toString());
    }

    @Test
    public void aPtrAnswerFillsTheHostnameWithoutTheFinalDot() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.arm();
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.NOERROR, "web.example.com."));
        assertEquals(1, results.size());
        assertEquals("web.example.com", results.get(0).hostname());
        assertEquals("ptr", results.get(0).reason());
        assertTrue(clock.tasks.get(0).isCancelled(), "the deadline was cancelled on completion");
    }

    @Test
    public void aReplyWithAnotherIdIsSomeoneElsesAndIsIgnored() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.onDatagram(reply(cb, cb.queryId() + 1, Rcode.NOERROR, "wrong.example.com."));
        assertTrue(results.isEmpty(), "still waiting for our answer");
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.NOERROR, "right.example.com."));
        assertEquals("right.example.com", results.get(0).hostname());
    }

    @Test
    public void nxdomainAndAnEmptyAnswerAreNoHostnameWithAReason() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.NXDOMAIN, null));
        assertNull(results.get(0).hostname());
        assertEquals("nxdomain", results.get(0).reason());

        results.clear();
        cb = lookup("10.0.0.2");
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.NOERROR, null));
        assertNull(results.get(0).hostname());
        assertEquals("no-answer", results.get(0).reason());

        results.clear();
        cb = lookup("10.0.0.3");
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.SERVFAIL, null));
        assertEquals("rcode:SERVFAIL", results.get(0).reason());
    }

    @Test
    public void garbageIsABadReply() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.onDatagram(new byte[]{1, 2, 3});
        assertEquals(1, results.size());
        assertNull(results.get(0).hostname());
        assertEquals("bad-reply", results.get(0).reason());
    }

    @Test
    public void silenceForTheDeadlineIsATimeout() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.arm();
        assertEquals(1, clock.tasks.size(), "one deadline, nothing else");
        assertEquals(ReverseDnsCallback.DEFAULT_TIMEOUT_MS, clock.tasks.get(0).delayMs);
        assertTrue(results.isEmpty());
        clock.tasks.get(0).run();
        assertEquals(1, results.size());
        assertNull(results.get(0).hostname());
        assertEquals("timeout", results.get(0).reason());
    }

    @Test
    public void completionIsExactlyOnceWhicheverArrivesFirst() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.arm();
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.NOERROR, "first.example.com."));
        clock.tasks.get(0).run();                                    // a late deadline
        cb.onDatagram(reply(cb, cb.queryId(), Rcode.NOERROR, "second.example.com."));
        cb.abort();                                                  // a late cancel
        cb.onError(new PortUnreachableException("ICMP Port Unreachable"));
        assertEquals(1, results.size());
        assertEquals("first.example.com", results.get(0).hostname(), "the first verdict stands");
    }

    @Test
    public void anIcmpErrorAndACancelAreReportedAsSuch() throws Exception {
        ReverseDnsCallback cb = lookup("10.0.0.1");
        cb.onError(new PortUnreachableException("ICMP Port Unreachable"));
        assertEquals("port-unreach", results.get(0).reason());

        results.clear();
        cb = lookup("10.0.0.2");
        cb.onError(new java.io.UncheckedIOException(new java.io.IOException("weird")));
        assertEquals("error:IOException", results.get(0).reason(), "a kickoff failure is classified by its cause");

        results.clear();
        cb = lookup("10.0.0.3");
        cb.arm();
        cb.abort();
        assertEquals("cancelled", results.get(0).reason());
        assertTrue(clock.tasks.get(0).isCancelled());
    }

    @Test
    public void resolverAddressPrefersTheLiteralAndNeverResolvesAName() {
        List<String> warnings = new ArrayList<>();
        InetSocketAddress a = ReverseDnsCallback.resolverAddress("1.1.1.1", warnings);
        assertEquals("1.1.1.1", a.getAddress().getHostAddress());
        assertEquals(ReverseDnsCallback.DNS_PORT, a.getPort());
        assertTrue(warnings.isEmpty());

        InetSocketAddress b = ReverseDnsCallback.resolverAddress("dns.example", warnings);
        assertNotNull(b, "a name falls back to the system resolver rather than blocking on a lookup");
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("dns.example"), warnings.get(0));

        InetSocketAddress c = ReverseDnsCallback.resolverAddress(null, warnings);
        assertNotNull(c);
        assertEquals(1, warnings.size(), "the default path adds no warning");
    }
}
