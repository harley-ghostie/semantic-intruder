package br.com.semanticburp;

import com.google.gson.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SemanticsTest {
    @Test void nestedMutationChangesOnlySelectedFieldAndPreservesOriginal() {
        JsonElement original = Semantics.parse("{\"cardId\":12,\"items\":[{\"cardId\":12,\"active\":true}]}");
        JsonElement modified = Semantics.replace(original, "/items/0/cardId", new JsonPrimitive(99));
        assertEquals(12, original.getAsJsonObject().getAsJsonArray("items").get(0).getAsJsonObject().get("cardId").getAsInt());
        assertEquals(Semantics.parse("{\"cardId\":12,\"items\":[{\"cardId\":99,\"active\":true}]}"), modified);
    }
    @Test void jsonPointerEscapesAndEmptyKeysWork() {
        JsonElement original = Semantics.parse("{\"a/b\":{\"~k\":{\"\":1}},\"\":2}");
        assertTrue(Semantics.leaves(original).containsKey("/a~1b/~0k/"));
        JsonElement changed = Semantics.replace(original, "/a~1b/~0k/", JsonNull.INSTANCE);
        assertTrue(changed.getAsJsonObject().getAsJsonObject("a/b").getAsJsonObject("~k").get("").isJsonNull());
        assertEquals(new JsonPrimitive(false), Semantics.replace(original, "", new JsonPrimitive(false)));
    }
    @Test void parserRejectsDuplicateKeysAndTrailingContentAndExcessiveDepth() {
        for (String bad : List.of("{\"id\":1,\"id\":2}", "{\"x\":{\"a\":1,\"a\":2}}", "{}[]", "{x:1}", "[NaN]", "[1,]", "[".repeat(66) + "1" + "]".repeat(66)))
            assertThrows(IllegalArgumentException.class, () -> Semantics.parse(bad), bad);
    }
    @Test void pairMutationPreservesRepeatedKeysUnrelatedEncodingAndOrder() {
        assertEquals("id=1&id=99&sig=a%2Bb+z&flag&", Semantics.replacePair("id=1&id=2&sig=a%2Bb+z&flag&", 1, "99"));
        assertEquals("id=1&flag=x%26y%3Dz", Semantics.replacePair("id=1&flag", 1, "x&y=z"));
    }
    @Test void pathAndQueryEncodingAreDistinct() {
        assertEquals("a%2Fb%20c%2Bd", Semantics.encode("a/b c+d", true));
        assertEquals("a/b c+d", Semantics.decode("a%2Fb%20c+d", true));
        assertEquals("a b+c", Semantics.decode("a+b%2Bc", false));
        assertEquals("ação_日本", Semantics.decode(Semantics.encode("ação_日本", false), false));
    }
    @Test void idsAreExplicitDeduplicatedAndKeepNumericJsonType() {
        var plan = Semantics.plan(Semantics.Meaning.IDENTIFIER, new JsonPrimitive(1), true, "1\n2\n2\n3", false);
        assertEquals(2, plan.size()); assertTrue(plan.stream().allMatch(Semantics.TestCase::authorization));
        assertTrue(plan.get(0).value().getAsJsonPrimitive().isNumber());
        assertEquals(2, plan.get(0).value().getAsInt());
    }
    @Test void stringIdsKeepLeadingZeros() {
        var plan = Semantics.plan(Semantics.Meaning.IDENTIFIER, new JsonPrimitive("001"), true, "002", false);
        assertTrue(plan.get(0).value().getAsJsonPrimitive().isString());
        assertEquals("002", plan.get(0).value().getAsString());
    }
    @Test void doesNotInventAlternativeIdsOrSendWithoutTests() {
        var plan = Semantics.plan(Semantics.Meaning.IDENTIFIER, new JsonPrimitive("a"), false, "", true);
        assertTrue(plan.stream().noneMatch(Semantics.TestCase::authorization));
        assertThrows(IllegalArgumentException.class, () -> Semantics.plan(Semantics.Meaning.IDENTIFIER, new JsonPrimitive("a"), false, "", false));
        assertThrows(IllegalArgumentException.class, () -> Semantics.plan(Semantics.Meaning.IDENTIFIER, new JsonPrimitive(1), true, "abc", false));
    }
    @Test void boundedPlanRejectsTooManyCases() {
        String ids = java.util.stream.IntStream.range(0, 51).mapToObj(Integer::toString).reduce("", (a,b) -> a + "\n" + b);
        assertThrows(IllegalArgumentException.class, () -> Semantics.plan(Semantics.Meaning.IDENTIFIER, new JsonPrimitive("original"), false, ids, false));
    }
    @Test void semanticFamiliesProduceDifferentTestsAndTypedValues() {
        var bool = Semantics.plan(Semantics.Meaning.BOOLEAN, new JsonPrimitive(true), true, "", true);
        assertTrue(bool.stream().anyMatch(t -> t.value().equals(new JsonPrimitive(false))));
        assertTrue(bool.stream().anyMatch(t -> t.value().equals(new JsonPrimitive("true"))));
        var number = Semantics.plan(Semantics.Meaning.NUMBER, new JsonPrimitive(5), true, "", true);
        assertTrue(number.stream().anyMatch(t -> t.value().equals(new JsonPrimitive(-1))));
        assertTrue(number.stream().noneMatch(t -> t.value().equals(new JsonPrimitive("A".repeat(256)))));
    }
    @Test void classifierIsEditableSuggestionWithBasicTypeRecognition() {
        assertEquals(Semantics.Meaning.IDENTIFIER, Semantics.classify("/accountId", new JsonPrimitive(9)));
        assertEquals(Semantics.Meaning.BOOLEAN, Semantics.classify("enabled", new JsonPrimitive("false")));
        assertEquals(Semantics.Meaning.NUMBER, Semantics.classify("amount", new JsonPrimitive("4.5")));
        assertEquals(Semantics.Meaning.STRING, Semantics.classify("name", new JsonPrimitive("Jane")));
    }
    @Test void jsonComparisonIgnoresOrderAndOnlyExplicitDynamicFields() {
        var result = Semantics.compare(200, "{\"id\":1,\"time\":1}", 200, "{\"time\":2,\"id\":1}", false, true, List.of("/time"));
        assertTrue(result.sameBody()); assertTrue(result.changes().isEmpty());
        var changed = Semantics.compare(200, "{\"id\":1,\"time\":1}", 200, "{\"time\":2,\"id\":2}", true, true, List.of("/time"));
        assertFalse(changed.sameBody()); assertEquals(List.of("/id"), changed.changes());
    }
    @Test void successNeverAutomaticallyConfirmsIdorEvenForDifferentOwner() {
        var result = Semantics.compare(200, "{\"owner\":\"A\"}", 200, "{\"owner\":\"B\"}", true, true, List.of());
        assertTrue(result.conclusion().contains("não confirma IDOR")); assertEquals(List.of("/owner"), result.changes());
    }
    @Test void missingAndUnstableResponsesRemainInconclusive() {
        assertTrue(Semantics.compare(200, "{}", 404, "{}", true, true, List.of()).conclusion().contains("inconclusivo"));
        assertTrue(Semantics.compare(401, "{}", 200, "{}", true, true, List.of()).conclusion().contains("Inconclusivo"));
        assertTrue(Semantics.compare(200, "{}", 200, "{}", true, false, List.of()).conclusion().contains("Inconclusivo"));
    }
    @Test void nonJsonComparisonUsesExactBodyAndRedirectIsNotSuccess() {
        assertFalse(Semantics.compare(200, "hello", 200, "other", false, true, List.of()).sameBody());
        assertTrue(Semantics.compare(200, "hello", 302, "", true, true, List.of()).conclusion().contains("Redirecionamento"));
    }
    @Test void fingerprintHasKnownSha256() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Semantics.sha256(new byte[0]));
    }
}
