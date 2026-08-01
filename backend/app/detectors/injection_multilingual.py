"""Multilingual prompt-injection signals.

The English pattern table in ``injection.py`` accumulated organically, and a
P15b diagnostic showed what that costs: French, Spanish, and German override
instructions produced **no detector hit at all**, while a Japanese one was
"caught" only because the gibberish detector fires on every non-Latin script.
Aggregate recall looked acceptable; per-slice recall on multilingual attacks
was 0.25, and one of that quarter was right for the wrong reason.

The fix is structural rather than a list of the sentences that failed. An
override injection has the same shape in every language this covers:

    <override verb> [scope] <instruction noun>        "ignore all previous instructions"
    <disclose verb> [possessive] <system-prompt noun> "reveal your system prompt"

So each language contributes vocabulary for those slots and the patterns are
built combinatorially. Adding a language is adding words, not authoring
regexes, which is what stops this table from drifting back toward whichever
sentences someone happened to test.

Two deliberate constraints:

* **Bounded gap.** Slots are joined with ``.{0,40}`` so "ignore … instructions"
  matches across intervening words without matching a paragraph that merely
  contains both somewhere. An unbounded gap turns any document discussing
  prompt injection into a detection.
* **No word boundaries for CJK.** Chinese, Japanese, and Korean do not
  delimit words with spaces, so ``\\b`` never matches inside them — a pattern
  written the English way silently never fires, which is exactly the failure
  that made the Japanese case look handled.

Scored slightly below the strongest English signals. These are shorter, more
literal patterns in languages where this module has no idiom coverage, so the
false-positive risk is higher and the confidence should say so.
"""

from __future__ import annotations

import re

# ── slot vocabulary, per language ──────────────────────────────────────────
#
# (override verbs, instruction nouns) and (disclose verbs, system-prompt nouns).
# Kept as raw alternations rather than finished patterns so the two families
# below stay the single place the regex shape is decided.

_LATIN = {
    # German. "Vergiss" was already covered in injection.py; "ignoriere",
    # "missachte", and the polite "Sie" forms were not — which is why
    # "Ignorieren Sie alle vorherigen Anweisungen" scored zero.
    "de": {
        "override": r"(?:ignorier(?:e|en)|missachte(?:n)?|vergiss|vergessen|verwirf)",
        "instruction": r"(?:anweisung(?:en)?|anleitung(?:en)?|regeln?|vorgaben?|befehl(?:e)?)",
        "disclose": r"(?:zeig(?:e|en)?|gib\s+aus|verrat(?:e|en)?|offenbar(?:e|en)?|nenn(?:e|en)?)",
        "systemprompt": r"(?:system\s?prompt|systemnachricht|systemmeldung|"
        r"(?:urspr[üu]nglichen?|internen?|versteckten?)\s+(?:regeln?|anweisungen?))",
    },
    "fr": {
        "override": r"(?:ignor(?:e|ez|er)|oubli(?:e|ez|er)|n[ée]glig(?:e|ez)|passe[zr]?\s+outre)",
        "instruction": r"(?:instructions?|consignes?|directives?|r[èe]gles?|ordres?)",
        "disclose": r"(?:r[ée]v[èe]l(?:e|ez|er)|affich(?:e|ez|er)|montr(?:e|ez|er)|donne[zr]?|dis|dites)",
        "systemprompt": r"(?:invite\s+syst[èe]me|message\s+syst[èe]me|prompt\s+syst[èe]me|"
        r"consignes?\s+initiales?|instructions?\s+(?:originales?|initiales?|cach[ée]es?))",
    },
    "es": {
        "override": r"(?:ignor(?:a|e|en|ar)|olvid(?:a|e|en|ar)|desestim(?:a|e)|haz\s+caso\s+omiso)",
        "instruction": r"(?:instruc(?:ci[óo]n|ciones)|indicaciones?|reglas?|[óo]rdenes?|directrices?)",
        "disclose": r"(?:revel(?:a|e|ar)|muestr(?:a|e)|mu[ée]stra|ens[ée][ñn]a|dime|di|imprime)",
        "systemprompt": r"(?:mensaje\s+de\s+sistema|prompt\s+de\s+sistema|indicaci[óo]n\s+del\s+sistema|"
        r"(?:reglas?|instruc(?:ci[óo]n|ciones))\s+(?:originales?|internas?|iniciales?|ocultas?))",
    },
    "it": {
        "override": r"(?:ignor(?:a|i|are)|dimentic(?:a|hi|are)|trascur(?:a|i)|non\s+considerare)",
        "instruction": r"(?:istruzion[ei]|indicazion[ei]|regole?|ordin[ei]|direttive?)",
        "disclose": r"(?:rivel(?:a|i|are)|mostr(?:a|i|are)|stamp(?:a|i)|dimmi|fammi\s+vedere)",
        "systemprompt": r"(?:prompt\s+di\s+sistema|messaggio\s+di\s+sistema|"
        r"(?:regole|istruzioni)\s+(?:original[ei]|intern[ei]|iniziali|nascost[ei]))",
    },
    "pt": {
        "override": r"(?:ignor(?:a|e|ar)|esque[çc](?:a|e|er)|desconsider(?:a|e|ar)|despreze)",
        "instruction": r"(?:instru[çc](?:[ãa]o|[õo]es)|indica[çc][õo]es|regras?|ordens?|diretrizes?)",
        "disclose": r"(?:revel(?:a|e|ar)|mostr(?:a|e|ar)|exib(?:a|e|ir)|diga|imprima)",
        "systemprompt": r"(?:prompt\s+de\s+sistema|mensagem\s+de\s+sistema|"
        r"(?:regras?|instru[çc][õo]es)\s+(?:originais|internas|iniciais|ocultas))",
    },
    "nl": {
        "override": r"(?:negeer|vergeet|sla\s+.{0,12}\s?over|verwerp)",
        "instruction": r"(?:instructies?|aanwijzingen?|regels?|opdrachten?|richtlijnen?)",
        "disclose": r"(?:toon|laat\s+.{0,12}\s?zien|onthul|geef\s+.{0,12}\s?weer|print)",
        "systemprompt": r"(?:systeemprompt|systeembericht|"
        r"(?:oorspronkelijke|interne|verborgen)\s+(?:regels?|instructies?))",
    },
    "pl": {
        "override": r"(?:zignoruj|ignoruj|zapomnij|pomi[ńn]|odrzu[ćc])",
        "instruction": r"(?:instrukcj[eęi]|polece[ńn]|wytyczn[ey]|zasad[yh]|regu[łl][yh])",
        "disclose": r"(?:poka[żz]|ujawnij|wy[śs]wietl|podaj|wypisz)",
        "systemprompt": r"(?:systemow[ye]\s+prompt|prompt\s+systemow[ye]|wiadomo[śs][ćc]\s+systemow[ąa]|"
        r"(?:pierwotn[ey]|ukryt[ey]|wewn[ęe]trzn[ey])\s+(?:zasad[yh]|instrukcj[eęi]))",
    },
    "tr": {
        "override": r"(?:yok\s+say|g[öo]rmezden\s+gel|unut|dikkate\s+alma)",
        "instruction": r"(?:talimatlar[ıi]?|y[öo]nergeler[ıi]?|kurallar[ıi]?|emirler[ıi]?)",
        "disclose": r"(?:g[öo]ster|a[çc][ıi]kla|yazd[ıi]r|s[öo]yle|ver)",
        "systemprompt": r"(?:sistem\s+istemi(?:ni)?|sistem\s+mesaj[ıi](?:n[ıi])?|"
        r"(?:orijinal|gizli|dahili)\s+(?:kurallar[ıi]?|talimatlar[ıi]?))",
    },
    "ru": {
        "override": r"(?:игнорир(?:уй|уйте|овать)|забудь(?:те)?|пренебрег(?:и|айте)|отбрось)",
        "instruction": r"(?:инструкци(?:ю|и|й|ями)|указани(?:е|я|й)|правил(?:а|о)|командам?и?)",
        "disclose": r"(?:покажи(?:те)?|раскрой(?:те)?|выведи(?:те)?|скажи(?:те)?|напечатай)",
        "systemprompt": r"(?:системн(?:ый|ое|ым)\s+(?:промпт|сообщение|запрос)|"
        r"(?:исходн(?:ые|ый)|скрыт(?:ые|ый)|внутренн(?:ие|ий))\s+(?:правила|инструкции))",
    },
}

# CJK: no spaces between words, so the patterns must not use \b anywhere, and
# the gap between slots is tighter because these scripts pack more meaning per
# character.
_CJK = {
    "zh": {
        "override": r"(?:忽略|无视|忽視|無視|忘记|忘記|不要理会|不用理會)",
        "instruction": r"(?:指令|指示|规则|規則|命令|提示)",
        "disclose": r"(?:显示|顯示|输出|輸出|告诉我|告訴我|revealed?|展示|打印)",
        "systemprompt": r"(?:系统提示词?|系統提示詞?|系统消息|系統訊息|原始指令|内部规则|內部規則)",
    },
    "ja": {
        "override": r"(?:無視し|無視して|忘れて|破棄して|従わないで)",
        "instruction": r"(?:指示|命令|ルール|規則|プロンプト)",
        "disclose": r"(?:表示して|出力して|教えて|見せて|開示して)",
        "systemprompt": r"(?:システムプロンプト|システムメッセージ|初期指示|内部ルール|隠された指示)",
    },
    "ko": {
        "override": r"(?:무시하(?:고|세요|십시오|라)|잊(?:고|어|으세요)|따르지\s?말)",
        "instruction": r"(?:지시|명령|규칙|지침|프롬프트)",
        "disclose": r"(?:출력하|보여\s?줘|알려\s?줘|표시하|공개하)",
        "systemprompt": r"(?:시스템\s?프롬프트|시스템\s?메시지|원래\s?지시|내부\s?규칙)",
    },
}

# Arabic: written right-to-left but matched left-to-right in codepoint order,
# which is the order the characters are stored in. Word boundaries do work
# here, but \b is unreliable against Arabic combining marks, so the same
# no-boundary approach is used.
_RTL = {
    "ar": {
        "override": r"(?:تجاهل|انس|تناس|لا\s+تلتزم|أهمل)",
        "instruction": r"(?:التعليمات|الأوامر|القواعد|التوجيهات)",
        "disclose": r"(?:أظهر|اعرض|اكشف|أخبرني|اطبع)",
        "systemprompt": r"(?:موجه\s+النظام|رسالة\s+النظام|التعليمات\s+(?:الأصلية|الداخلية|المخفية))",
    },
}

# How far apart the two slots may sit. Bounded so "ignore … instructions"
# cannot match across a paragraph that merely mentions both.
_GAP = r".{0,40}"

# Below the strongest English signals (0.8-0.85) on purpose: these are shorter,
# more literal patterns in languages where this module carries no idiom
# coverage, so their false-positive risk is higher and the score should admit
# it. Still above the 0.5 detector threshold, so one clean match is a hit.
_OVERRIDE_WEIGHT = 0.72
_DISCLOSE_WEIGHT = 0.72


def _build() -> tuple[tuple[re.Pattern[str], float], ...]:
    """Both word orders, for every language.

    The first cut emitted only ``verb … object``, which is the order in English
    and in the Romance, Germanic, and Slavic languages here. It silently missed
    every VERB-FINAL language: Turkish "talimatları yok say" is literally
    "instructions ignore", and Japanese and Korean put the verb last too. The
    held-out set caught it on Turkish.

    Emitting the reverse as well is the general fix — it covers any SOV
    language rather than the one that happened to fail. It costs little on SVO
    text, where "instructions … ignore" within 40 characters is an unusual
    construction, and the benign corpora are what decide whether that judgement
    holds.
    """
    signals: list[tuple[re.Pattern[str], float]] = []
    for table, word_bounded in ((_LATIN, True), (_CJK, False), (_RTL, False)):
        for slots in table.values():
            b = r"\b" if word_bounded else ""
            # Romance languages attach clitic pronouns to the verb —
            # "mostrami", "muéstrame", "dimmelo" — so a trailing \b right
            # after the verb stem never matches. Allowing a few extra word
            # characters covers that generally (and Germanic/Slavic inflection
            # with it) instead of enumerating pronouns per language. Latin
            # script only: \w would happily swallow neighbouring CJK.
            clitic = r"\w{0,3}" if word_bounded else ""
            for verb, obj, weight in (
                (slots["override"] + clitic, slots["instruction"], _OVERRIDE_WEIGHT),
                (slots["disclose"] + clitic, slots["systemprompt"], _DISCLOSE_WEIGHT),
            ):
                for first, second in ((verb, obj), (obj, verb)):
                    signals.append(
                        (
                            re.compile(
                                f"{b}{first}{b}{_GAP}{b}{second}{b}",
                                re.IGNORECASE | re.UNICODE,
                            ),
                            weight,
                        )
                    )
    return tuple(signals)


MULTILINGUAL_PI_SIGNALS: tuple[tuple[re.Pattern[str], float], ...] = _build()

SUPPORTED_LANGUAGES: tuple[str, ...] = tuple(sorted({*_LATIN, *_CJK, *_RTL}))
