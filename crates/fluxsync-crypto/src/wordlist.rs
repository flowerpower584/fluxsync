//! 6-word fingerprint wordlist.
//!
//! Source: BIP-39 English wordlist
//! (<https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt>),
//! public domain. The full BIP-39 list contains 2048 entries that were already
//! curated by the spec authors to avoid same-spelling near-homophones and
//! similar typing-pair confusions.
//!
//! Curation applied here:
//!   1. Keep only entries 4 ≤ len ≤ 7. The very-short words ("act", "add",
//!      "age") are easy to mis-hear over a phone call; the longer words
//!      ("kingdom", "abstract") slow down verbal compare without paying back
//!      in entropy.
//!   2. Truncate to exactly 1024 entries, in source order.
//!
//! 1024 = 10 bits per word. A 6-word fingerprint therefore commits to 60 bits
//! of the BLAKE3 hash of the static public key — enough to make a fingerprint
//! collision search visible to a user reading words aloud while the
//! attacker scrambles their X25519 keypair.
//!
//! If you need to regenerate this file, the recipe is:
//!     curl -sL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt \
//!       | awk 'length($0) >= 4 && length($0) <= 7' | head -1024
//!
//! The order is part of the wire-derivable fingerprint; do **not** sort or
//! reshuffle without bumping the protocol version.

pub const WORDLIST: [&str; 1024] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "absurd", "abuse",
    "access", "account", "accuse", "achieve", "acid", "acquire", "across", "action", "actor",
    "actress", "actual", "adapt", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "agent", "agree", "ahead",
    "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "alley", "allow", "almost",
    "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
    "ankle", "annual", "another", "answer", "antenna", "antique", "anxiety", "apart", "apology",
    "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "artist", "artwork",
    "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack",
    "attend", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bacon", "badge", "balance", "balcony", "ball", "bamboo", "banana", "banner", "barely",
    "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because",
    "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bike", "bind",
    "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
    "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat",
    "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick",
    "bridge", "brief", "bright", "bring", "brisk", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "busy", "butter", "buyer", "buzz", "cabbage", "cabin",
    "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "canal", "cancel",
    "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "carbon",
    "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
    "catalog", "catch", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery",
    "cement", "census", "century", "cereal", "certain", "chair", "chalk", "change", "chaos",
    "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest",
    "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk",
    "churn", "cigar", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw",
    "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip",
    "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column",
    "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
    "connect", "control", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack",
    "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
    "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "crystal", "cube", "culture",
    "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "damage",
    "damp", "dance", "danger", "daring", "dash", "dawn", "deal", "debate", "debris", "decade",
    "decide", "decline", "deer", "defense", "define", "defy", "degree", "delay", "deliver",
    "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth",
    "deputy", "derive", "desert", "design", "desk", "despair", "destroy", "detail", "detect",
    "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet",
    "differ", "digital", "dignity", "dilemma", "dinner", "direct", "dirt", "disease", "dish",
    "dismiss", "display", "divert", "divide", "divorce", "dizzy", "doctor", "doll", "dolphin",
    "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon",
    "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive",
    "drop", "drum", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic",
    "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology",
    "economy", "edge", "edit", "educate", "effort", "eight", "either", "elbow", "elder", "elegant",
    "element", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
    "empower", "empty", "enable", "enact", "endless", "endorse", "enemy", "energy", "enforce",
    "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure",
    "enter", "entire", "entry", "episode", "equal", "equip", "erase", "erode", "erosion", "error",
    "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evil", "evoke",
    "evolve", "exact", "example", "excess", "excite", "exclude", "excuse", "execute", "exhaust",
    "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain",
    "expose", "express", "extend", "extra", "eyebrow", "fabric", "face", "faculty", "fade",
    "faint", "faith", "fall", "false", "fame", "family", "famous", "fancy", "fantasy", "farm",
    "fashion", "fatal", "father", "fatigue", "fault", "feature", "federal", "feed", "feel",
    "female", "fence", "fetch", "fever", "fiber", "fiction", "field", "figure", "file", "film",
    "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal",
    "fish", "fitness", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip",
    "float", "flock", "floor", "flower", "fluid", "flush", "foam", "focus", "foil", "fold",
    "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward",
    "fossil", "foster", "found", "fragile", "frame", "fresh", "friend", "fringe", "frog", "front",
    "frost", "frown", "frozen", "fruit", "fuel", "funny", "furnace", "fury", "future", "gadget",
    "gain", "galaxy", "gallery", "game", "garage", "garbage", "garden", "garlic", "garment",
    "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine",
    "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad",
    "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow",
    "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern",
    "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green",
    "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide",
    "guilt", "guitar", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor",
    "hard", "harsh", "harvest", "have", "hawk", "hazard", "head", "health", "heart", "heavy",
    "height", "hello", "helmet", "help", "hero", "hidden", "high", "hill", "hint", "hire",
    "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood",
    "hope", "horn", "horror", "horse", "host", "hotel", "hour", "hover", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "icon",
    "idea", "idle", "ignore", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "index", "indoor",
    "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate",
    "inner", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact",
    "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
    "jacket", "jaguar", "jazz", "jealous", "jeans", "jelly", "jewel", "join", "joke", "journey",
    "judge", "juice", "jump", "jungle", "junior", "junk", "just", "keen", "keep", "ketchup",
    "kick", "kidney", "kind", "kingdom", "kiss", "kitchen", "kite", "kitten", "kiwi", "knee",
    "knife", "knock", "know", "label", "labor", "ladder", "lady", "lake", "lamp", "laptop",
    "large", "later", "latin", "laugh", "laundry", "lava", "lawn", "lawsuit", "layer", "lazy",
    "leader", "leaf", "learn", "leave", "lecture", "left", "legal", "legend", "leisure", "lemon",
    "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
    "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list",
    "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely",
    "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
    "lunar", "lunch", "luxury", "lyrics", "machine", "magic", "magnet", "maid", "mail", "main",
    "major", "make", "mammal", "manage", "mandate", "mango", "mansion", "manual", "maple",
    "marble", "march", "margin", "marine", "market", "mask", "mass", "master", "match", "math",
    "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "medal", "media",
    "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
    "mesh", "message", "metal", "method", "middle", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
];
