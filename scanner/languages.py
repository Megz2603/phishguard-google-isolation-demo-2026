LANGUAGES = [
    {"code": "en", "name": "English"},
    {"code": "af", "name": "Afrikaans"},
    {"code": "nr", "name": "isiNdebele"},
    {"code": "xh", "name": "isiXhosa"},
    {"code": "zu", "name": "isiZulu"},
    {"code": "nso", "name": "Sepedi"},
    {"code": "st", "name": "Sesotho"},
    {"code": "tn", "name": "Setswana"},
    {"code": "ss", "name": "siSwati"},
    {"code": "ve", "name": "Tshivenda"},
    {"code": "ts", "name": "itsonga"},
]

# Weight reflects how strongly each phrase signals credential theft, coercion,
# payment pressure, or generic urgency.
KEYWORDS_BY_LANGUAGE = {
    "en": [
        ("urgent", 7), ("immediately", 7), ("account suspended", 12),
        ("account closed", 11), ("verify your account", 14),
        ("verify your identity", 14), ("password", 12), ("credit card", 12),
        ("bank account", 12), ("payment required", 11), ("click here", 8),
        ("confirm your account", 13), ("security alert", 9),
        ("unusual activity", 10), ("login", 7), ("winner", 5),
        ("congratulations", 4), ("you have won", 6),
    ],
    "af": [
        ("dringend", 7), ("onmiddellik", 7), ("rekening opgeskort", 12),
        ("rekening gesluit", 11), ("verifieer jou rekening", 14),
        ("verifieer jou identiteit", 14), ("wagwoord", 12),
        ("kredietkaart", 12), ("bankrekening", 12),
        ("betaling vereis", 11), ("klik hier", 8),
        ("bevestig jou rekening", 13), ("sekuriteitswaarskuwing", 9),
        ("ongewone aktiwiteit", 10), ("aanmeld", 7), ("wenner", 5),
        ("geluk", 4), ("jy het gewen", 6),
        ("dringende", 7), ("rekening onmiddellik verifieer", 14),
        ("aanmeldaktiwiteit", 7),
    ],
    "nr": [
        ("ngokurhabako", 7), ("khonokho", 7), ("i-akhawundi yakho ivaliwe", 12),
        ("i-akhawundi ivaliwe", 11), ("qinisekisa i-akhawundi yakho", 14),
        ("qinisekisa ubunikazi bakho", 14), ("iphasiwedi", 12),
        ("ikhadi lesikweledu", 12), ("i-akhawundi yebhanga", 12),
        ("kubhadalwa kuyadingeka", 11), ("gandelela lapha", 8),
        ("veza i-akhawundi yakho", 13), ("isilumkiso sezokuphepha", 9),
        ("umsebenzi ongakajayeleki", 10), ("ngena", 7), ("umnqobi", 5),
        ("siyakuhalalisela", 4), ("uphumelele", 6),
    ],
    "xh": [
        ("ngokukhawuleza", 7), ("ngoko nangoko", 7),
        ("iakhawunti yakho imisiwe", 12), ("iakhawunti ivaliwe", 11),
        ("qinisekisa iakhawunti yakho", 14), ("qinisekisa isazisi sakho", 14),
        ("igama lokugqitha", 12), ("ikhadi letyala", 12),
        ("iakhawunti yebhanki", 12), ("intlawulo iyafuneka", 11),
        ("cofa apha", 8), ("qinisekisa iakhawunti yakho", 13),
        ("isilumkiso sokhuseleko", 9), ("umsebenzi ongaqhelekanga", 10),
        ("ngena", 7), ("ophumeleleyo", 5), ("sivuyisana nawe", 4),
        ("uphumelele", 6),
    ],
    "zu": [
        ("ngokushesha", 7), ("ngokushesha kakhulu", 7),
        ("i-akhawunti yakho imisiwe", 12), ("i-akhawunti ivaliwe", 11),
        ("qinisekisa i-akhawunti yakho", 14), ("qinisekisa ubuwena", 14),
        ("iphasiwedi", 12), ("ikhadi lesikweletu", 12),
        ("i-akhawunti yasebhange", 12), ("inkokhelo iyadingeka", 11),
        ("chofoza lapha", 8), ("qinisekisa i-akhawunti yakho", 13),
        ("isexwayiso sokuphepha", 9), ("umsebenzi ongajwayelekile", 10),
        ("ngena", 7), ("owinile", 5), ("siyakuhalalisela", 4),
        ("uwinile", 6),
    ],
    "nso": [
        ("ka pela", 7), ("gatee", 7), ("akhaonto ya gago e emišitšwe", 12),
        ("akhaonto e tswaletšwe", 11), ("netefatša akhaonto ya gago", 14),
        ("netefatša boitsebišo bja gago", 14), ("lentšu la sephiri", 12),
        ("karata ya mokitlana", 12), ("akhaonto ya panka", 12),
        ("tefo e a nyakega", 11), ("kgotla mo", 8),
        ("netefatša akhaonto ya gago", 13), ("temošo ya tšhireletšo", 9),
        ("tiragalo ye e sa tlwaelegago", 10), ("tsena", 7), ("mothopasefoka", 5),
        ("re a go lebogiša", 4), ("o fentše", 6),
    ],
    "st": [
        ("ka potlako", 7), ("hang-hang", 7), ("ak'haonte ea hau e emisitsoe", 12),
        ("ak'haonte e koetsoe", 11), ("netefatsa ak'haonte ea hau", 14),
        ("netefatsa boitsebiso ba hau", 14), ("phasewete", 12),
        ("karete ea mokitlane", 12), ("ak'haonte ea banka", 12),
        ("tefo ea hlokahala", 11), ("tobetsa mona", 8),
        ("netefatsa ak'haonte ea hau", 13), ("temoso ea tšireletso", 9),
        ("ketso e sa tloaelehang", 10), ("kena", 7), ("mohloli", 5),
        ("rea u leboha", 4), ("u hapile", 6),
    ],
    "tn": [
        ("ka bonako", 7), ("ka ponyo ya leitlho", 7),
        ("akhaonto ya gago e emisitswe", 12), ("akhaonto e tswetswe", 11),
        ("netefatsa akhaonto ya gago", 14),
        ("netefatsa boitshupo jwa gago", 14), ("phasewete", 12),
        ("karata ya sekoloto", 12), ("akhaonto ya banka", 12),
        ("tuelo e a tlhokega", 11), ("tobetsa fano", 8),
        ("netefatsa akhaonto ya gago", 13), ("tlhagiso ya tshireletso", 9),
        ("tiragalo e e sa tlwaelegang", 10), ("tsena", 7), ("mofenyi", 5),
        ("re a go leboga", 4), ("o fentse", 6),
    ],
    "ss": [
        ("masinyane", 7), ("khona manje", 7),
        ("i-akhawunti yakho imisiwe", 12), ("i-akhawunti ivaliwe", 11),
        ("cinisekisa i-akhawunti yakho", 14), ("cinisekisa kutsi ungubani", 14),
        ("libitophasi", 12), ("likhadi lesikweleti", 12),
        ("i-akhawunti yasebhange", 12), ("inkhokhelo iyadzingeka", 11),
        ("chafata lapha", 8), ("cinisekisa i-akhawunti yakho", 13),
        ("secwayiso sekuphepha", 9), ("umsebenti longakavami", 10),
        ("ngena", 7), ("umnqobi", 5), ("siyakuhalalisela", 4),
        ("uwinile", 6),
    ],
    "ve": [
        ("nga u ṱavhanya", 7), ("zwino", 7),
        ("akhaunthu yanu yo imiswa", 12), ("akhaunthu yo valiwa", 11),
        ("khwaṱhisedzani akhaunthu yanu", 14),
        ("khwaṱhisedzani vhuṋe haṋu", 14), ("phasiwede", 12),
        ("garaṱa ya khirediti", 12), ("akhaunthu ya bannga", 12),
        ("mbadelo i a ṱoḓea", 11), ("puṱedzani hafha", 8),
        ("khwaṱhisedzani akhaunthu yanu", 13),
        ("tsivhudzo ya tsireledzo", 9), ("nyito i songo ḓoweleaho", 10),
        ("logani", 7), ("muwini", 5), ("ri a ni takalela", 4), ("no wina", 6),
    ],
    "ts": [
        ("hi ku hatlisa", 7), ("sweswi", 7),
        ("akhawunti ya wena yi yimisiwile", 12), ("akhawunti yi pfariwile", 11),
        ("tiyisisa akhawunti ya wena", 14),
        ("tiyisisa vun'winyi bya wena", 14), ("phasiwedi", 12),
        ("khadi ra xikweleti", 12), ("akhawunti ya bangi", 12),
        ("hakelo ya laveka", 11), ("tinya laha", 8),
        ("tiyisisa akhawunti ya wena", 13), ("xitsundzuxo xa vuhlayiseki", 9),
        ("ntirho lowu nga tolovelekangiki", 10), ("ngena", 7), ("muhleri", 5),
        ("ha ku hoyozela", 4), ("u hlurile", 6),
    ],
}

LANGUAGE_NAMES = {language["code"]: language["name"] for language in LANGUAGES}
DEFAULT_PRIMARY_LANGUAGE = "en"
DEFAULT_SECONDARY_LANGUAGES = []


def normalize_language_preferences(primary_language, secondary_languages):
    valid_codes = set(LANGUAGE_NAMES)
    if not isinstance(primary_language, str) or primary_language not in valid_codes:
        raise ValueError("Choose a supported primary language.")
    if not isinstance(secondary_languages, list):
        raise ValueError("Secondary languages must be a list.")
    if any(
        not isinstance(code, str) or code not in valid_codes
        for code in secondary_languages
    ):
        raise ValueError("Choose only supported secondary languages.")
    ordered_secondary = []
    for code in secondary_languages:
        if code != primary_language and code not in ordered_secondary:
            ordered_secondary.append(code)
    return {
        "primary_language": primary_language,
        "secondary_languages": ordered_secondary,
    }
