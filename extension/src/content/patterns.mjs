// SPDX-License-Identifier: AGPL-3.0-only
// Modified by Faithful Ferret: the one-time-code terms (OTP_TERMS, OTP_WEAK_TERMS) and the search and filter
// terms (SEARCH_TERMS) are taken from apps/browser-extension/src/utils/formDetector/FieldPatterns.ts of AliasVault
// (https://github.com/aliasvault/aliasvault, commit 7e7cd6f3141c94f884ddd1666987aec3ffcdcdf3, GNU Affero General
// Public License v3): the English and Dutch `totp` include terms (specific and generic) and the English and Dutch
// field exclusion terms for search and filter boxes. Changed: the terms are written the way this file compares text
// (lower case, separators as spaces), "pin-code" and "pincode" are PIN terms here (a PIN is a kind of its own),
// "security-code" is checked after the card terms (a card's security code is not a one-time code), the settings and
// configuration terms of the exclusion list are left out, and German, Norwegian and French terms are added. Every
// other list in this file (user name, e-mail, password, new, confirm, current, card, PIN, name, coupon, and the
// words of a form's purpose and of its submit control) is Faithful Ferret's own. The original file has no header.
//
// The words that name what a field or a form is for, in English, Norwegian, German, French and Dutch. They are
// read by forms.mjs, after the `autocomplete` tokens: a token the page gives decides first, a word only when there
// is no token that says it. Nothing here decides alone that a value may go somewhere; forms.mjs combines the words
// with the field's type and its group.
//
// How text is compared (`normalize`): lower case, Unicode NFKC, a capital inside a word starts a new word
// (`newPassword` reads as `new password`), and `_ - . [ ] : / ( ) # +` read as spaces. A term of three characters
// or fewer must stand as a word of its own (`pin` is not in `spinner`); a longer one may be part of a word, which
// the compound words of German, Norwegian and Dutch need (`bestätigungscode`).

/**
 * The text of an attribute or a label as the lists compare it.
 * @param {unknown} text
 * @returns {string}
 */
export function normalize(text) {
  if (typeof text !== "string" || text === "") return "";
  const spaced = text.slice(0, 512).replace(/([a-zß-ÿ])([A-Z])/g, "$1 $2");
  return spaced
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[_\-.[\]:/()#+'"’,;!?*|]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** @param {string} term */
const escape = (term) => term.replace(/[$()*+.?[\\\]^{|}]/g, "\\$&");

/**
 * One regular expression for a list of terms (see the head of the file for the word rule).
 * @param {readonly string[]} terms
 * @returns {RegExp}
 */
export function termsRegex(terms) {
  const short = terms.filter((t) => t.length <= 3).map(escape);
  const long = terms.filter((t) => t.length > 3).map(escape);
  const parts = [];
  if (short.length > 0) parts.push(`(?:^|[^a-z0-9\\u00df-\\u00ff])(?:${short.join("|")})(?=$|[^a-z0-9\\u00df-\\u00ff])`);
  if (long.length > 0) parts.push(`(?:${long.join("|")})`);
  return new RegExp(parts.join("|"));
}

// ------------------------------------------------------------------ from AliasVault (see the header)

/** Terms that mark a one-time-code field on their own. */
export const OTP_TERMS = Object.freeze([
  // AliasVault, English `totp.include.specific` (without "pin-code", "pincode" and "security-code", see the header)
  "totp", "otp", "one time", "onetime", "six digit", "digit code", "authenticator", "authentication", "2fa", "twofa",
  "two factor", "mfa", "auth code", "google code", "verification code", "verificationcode", "tfa", "tfacode",
  "second factor", "one time password",
  // AliasVault, Dutch `totp.include.specific`
  "verificatiecode", "eenmalig", "authenticatie", "tweefactor", "beveiligingscode",
  // Faithful Ferret: German, Norwegian and French
  "bestätigungscode", "bestatigungscode", "verifizierungscode", "einmalcode", "einmalpasswort", "einmal passwort",
  "einmalkennwort", "einmal kennwort", "zwei faktor", "engangs passord", "usage unique", "mot de passe unique",
  "engangskode", "engangspassord", "bekreftelseskode", "verifiseringskode", "kode fra sms", "sms kode", "sms code",
  "tofaktor", "to faktor", "code de vérification", "code de verification", "code à usage unique", "code unique",
  "double authentification", "code d authentification",
]);

/** Terms too weak to mark a one-time-code field alone: they count only with a short numeric field (forms.mjs). */
export const OTP_WEAK_TERMS = Object.freeze([
  // AliasVault, English `totp.include.generic`
  "token", "code", "passcode",
  // Faithful Ferret
  "kode", "sicherheitscode", "sikkerhetskode", "code de sécurité", "security code",
]);

/** Terms of a site search or a filter box, which never gets a user name. */
export const SEARCH_TERMS = Object.freeze([
  // AliasVault, English and Dutch exclusion terms for search and filter boxes
  "search", "find", "lookup", "searchbox", "search box", "searchfield", "search field", "searchinput", "search input",
  "searchquery", "search query", "filter", "filterable", "filterinput", "filter input", "filterfield", "filter field",
  "filterbox", "filter box", "zoeken", "zoek", "zoekveld", "zoek veld", "zoekinput", "zoek input", "zoekbox",
  "zoek box", "filteren", "filterveld", "filter veld",
  // Faithful Ferret
  "suche", "suchen", "søk", "søke", "recherche", "rechercher", "query",
]);

// ------------------------------------------------------------------ Faithful Ferret's own lists

/** A user name (an account name, a login id). Checked before NAME_TERMS: `benutzername` holds `name`. */
export const USERNAME_TERMS = Object.freeze([
  "user", "login", "log in", "sign in", "signin", "identifier", "account", "acct", "uid",
  "player id", "playerid", "member id", "memberid", "customer id", "customerid", "client id", "clientid",
  "benutzer", "kennung", "anmeldename", "brukernavn", "bruker", "brukerid", "gebruiker", "gebruikersnaam",
  "identifiant", "utilisateur", "pseudo",
]);

/** An e-mail address. */
export const EMAIL_TERMS = Object.freeze([
  "email", "e mail", "mail", "epost", "e post", "courriel", "e mailadres", "emailadres", "mailadresse",
]);

/** A phone number (never a user name unless the page's autocomplete token says so). */
export const PHONE_TERMS = Object.freeze([
  "tel", "phone", "area code", "dial code", "country code", "landskode", "vorwahl", "indicatif", "telephone", "téléphone", "telefon", "telefoon", "mobil", "mobile", "mobilnummer", "handy",
  "portable", "gsm",
]);

/** A person's name or another personal field: never a user name. */
export const NAME_TERMS = Object.freeze([
  "name", "full name", "fullname", "first name", "firstname", "last name", "lastname", "surname", "given name",
  "family name", "nickname", "display name", "vorname", "nachname", "vollständiger name", "navn", "fornavn",
  "etternavn", "fullt navn", "kallenavn", "visningsnavn", "nom", "prénom", "prenom", "nom complet", "naam",
  "voornaam", "achternaam", "volledige naam", "street", "address", "adresse", "adres", "straat", "postcode", "zip",
  "postleitzahl", "postnummer", "code postal", "sort code", "bank code", "bankleitzahl",
  "postal", "city", "stadt", "ville", "plaats", "company", "firma", "message", "nachricht", "melding", "bericht",
  "comment", "kommentar", "commentaire", "subject", "betreff", "sujet", "onderwerp",
]);

/** A password (of any kind). */
export const PASSWORD_TERMS = Object.freeze([
  "password", "passwort", "passord", "passwd", "pass", "pwd", "kennwort", "mot de passe", "motdepasse", "mdp",
  "wachtwoord", "secret", "geheim", "passphrase",
]);

/** A field that sets a new password. */
export const NEW_TERMS = Object.freeze([
  "new", "neu", "neue", "neues", "ny", "nytt", "nye", "nouveau", "nouvelle", "nieuw", "nieuwe", "choose", "create",
  "wählen", "velg", "choisissez", "kies",
]);

/** A field that repeats a new password. */
export const CONFIRM_TERMS = Object.freeze([
  "confirm", "confirmation", "repeat", "retype", "re enter", "reenter", "again", "verify", "bestätig", "bestatig",
  "wiederhol", "gjenta", "bekreft", "confirmer", "confirmez", "répéter", "repeter", "retapez", "bevestig", "herhaal",
  "check",
]);

/** A field for the password in use now (a change form). */
export const CURRENT_TERMS = Object.freeze([
  "current", "old", "existing", "present", "aktuell", "aktuelles", "bisherig", "alt", "altes", "nåværende",
  "navarende", "gammelt", "gammel", "actuel", "ancien", "huidig", "huidige", "oud", "oude",
]);

/** A card's security code. */
export const CVC_TERMS = Object.freeze([
  "cvc", "cvv", "cvv2", "cvc2", "csc", "cvn", "cid", "card verification", "card security", "kartenprüfnummer",
  "prüfnummer", "pruefnummer", "kortkode", "cryptogramme", "kaartcode",
]);

/** A card number. */
export const CARD_TERMS = Object.freeze([
  "card number", "cardnumber", "ccnum", "cc number", "kortnummer", "kartennummer", "numéro de carte",
  "numero de carte", "kaartnummer", "credit card", "kredittkort", "kreditkarte", "carte bancaire",
]);

/** The other fields of a card (its expiry, its holder): never a user name. */
export const CARD_FIELD_TERMS = Object.freeze([
  "expiry", "expiration", "exp date", "ablauf", "gültig bis", "utløp", "utløpsdato", "date d expiration", "vervaldatum",
  "card holder", "cardholder", "name on card", "kortholder", "navn på kortet", "karteninhaber", "titulaire",
  "kaarthouder",
]);

/** A PIN (a short secret that is not the account's password). */
export const PIN_TERMS = Object.freeze(["pin", "pins", "pincode", "pin code", "code pin", "pin nummer", "pinkode"]);

/** A coupon or gift code (never a one-time code). */
export const COUPON_TERMS = Object.freeze([
  "coupon", "voucher", "promo", "discount", "gift card", "giftcard", "gutschein", "rabatt", "kupong", "rabattkode",
  "gavekort", "kortingscode", "cadeau", "bon de réduction", "code promo",
]);

// ------------------------------------------------------------------ the words of a form's purpose

/** A sign-in. */
export const LOGIN_WORDS = Object.freeze([
  "log in", "login", "log on", "logon", "sign in", "signin", "anmelden", "einloggen", "logg inn", "logge inn",
  "pålogging", "innlogging", "se connecter", "connexion", "connectez", "identifiez", "inloggen",
]);

/** The step of a sign-in that asks for the user name first and then moves on. */
export const NEXT_WORDS = Object.freeze([
  "next", "continue", "proceed", "weiter", "fortfahren", "neste", "fortsett", "videre", "suivant", "continuer",
  "volgende", "doorgaan", "verder",
]);

/** A new account. */
export const SIGNUP_WORDS = Object.freeze([
  "sign up", "signup", "register", "registration", "create account", "create an account", "create your account",
  "join", "registrieren", "registrierung", "konto erstellen", "konto anlegen", "opprett konto", "opprett en konto",
  "registrer", "bli medlem", "créer un compte", "creer un compte", "créer mon compte", "s inscrire", "inscription",
  "account aanmaken", "registreren", "maak account", "maak een account",
]);

/** A reset of a forgotten password. */
export const RESET_WORDS = Object.freeze([
  "reset", "forgot", "recover", "zurücksetzen", "zurucksetzen", "vergessen", "tilbakestill", "glemt",
  "réinitialiser", "reinitialiser", "oublié", "opnieuw instellen", "herstel", "vergeten",
]);

/** A form that is not a sign-in although it has an e-mail field: a newsletter, a contact or feedback form. */
export const NOT_LOGIN_WORDS = Object.freeze([
  "newsletter", "subscribe", "abonnieren", "abonner", "abonnement", "nyhetsbrev", "nyheter", "nieuwsbrief",
  "nouveautés", "nouveautes", "actualités", "news", "contact", "kontakt", "nachricht", "message", "melding",
  "bericht", "feedback", "bewertung", "tilbakemelding", "avis", "commentaire", "comment", "kommentar", "send",
  "senden", "envoyer", "versturen", "verzenden",
]);

/** A control that shows or hides the password (never a submit control). */
export const SHOW_WORDS = Object.freeze([
  "show", "hide", "reveal", "vis", "skjul", "anzeigen", "zeigen", "verbergen", "ausblenden", "afficher", "masquer",
  "toon", "verberg",
]);

/**
 * The words of a submit control, per language (the capture script's click rule uses them too): a control whose
 * text has one of them sends the form.
 */
export const SUBMIT_WORDS = Object.freeze({
  en: Object.freeze(["log in", "login", "sign in", "sign up", "register", "create account", "create user", "submit", "continue", "next", "save", "change password", "reset password", "update password", "confirm", "verify"]),
  nb: Object.freeze(["logg inn", "logg på", "registrer", "opprett konto", "opprett bruker", "send", "fortsett", "neste", "lagre", "bytt passord", "endre passord", "tilbakestill", "bekreft"]),
  de: Object.freeze(["anmelden", "einloggen", "registrieren", "konto erstellen", "benutzer erstellen", "absenden", "weiter", "fortfahren", "speichern", "passwort ändern", "zurücksetzen", "bestätigen", "prüfen"]),
  fr: Object.freeze(["se connecter", "connexion", "s inscrire", "créer un compte", "créer mon compte", "envoyer", "continuer", "suivant", "enregistrer", "changer le mot de passe", "réinitialiser", "confirmer", "vérifier"]),
  nl: Object.freeze(["inloggen", "aanmelden", "registreren", "account aanmaken", "gebruiker aanmaken", "versturen", "doorgaan", "volgende", "opslaan", "wachtwoord wijzigen", "bevestigen", "controleren"]),
});

/**
 * A one-time password by its own words, in the five languages, with or without the space or hyphen: such a field is
 * a one-time code although it names a password.
 */
export const ONE_TIME_PASSWORD = /one ?time pass|einmal ?(?:pass|kenn)wort|engangs ?passord|eenmalig(?:e)? ?wachtwoord|mot de passe (?:a |à )?(?:usage )?unique/;

// ------------------------------------------------------------------ compiled

export const OTP = termsRegex(OTP_TERMS);
export const OTP_WEAK = termsRegex(OTP_WEAK_TERMS);
export const SEARCH = termsRegex(SEARCH_TERMS);
export const USERNAME = termsRegex(USERNAME_TERMS);
export const EMAIL = termsRegex(EMAIL_TERMS);
export const PHONE = termsRegex(PHONE_TERMS);
export const NAME = termsRegex(NAME_TERMS);
export const PASSWORD = termsRegex(PASSWORD_TERMS);
export const NEW = termsRegex(NEW_TERMS);
export const CONFIRM = termsRegex(CONFIRM_TERMS);
export const CURRENT = termsRegex(CURRENT_TERMS);
export const CVC = termsRegex(CVC_TERMS);
export const CARD = termsRegex(CARD_TERMS);
export const CARD_FIELD = termsRegex(CARD_FIELD_TERMS);
export const PIN = termsRegex(PIN_TERMS);
export const COUPON = termsRegex(COUPON_TERMS);
// "anmelden" (de: sign in) is also the end of "aanmelden" (nl: sign up or sign in), which says neither.
export const LOGIN = new RegExp(`(?<!a)anmelden|${termsRegex(LOGIN_WORDS.filter((w) => w !== "anmelden")).source}`);
export const NEXT = termsRegex(NEXT_WORDS);
export const SIGNUP = termsRegex(SIGNUP_WORDS);
export const RESET = termsRegex(RESET_WORDS);
export const NOT_LOGIN = termsRegex(NOT_LOGIN_WORDS);
export const SUBMIT = termsRegex(Object.values(SUBMIT_WORDS).flat());
export const SHOW = termsRegex(SHOW_WORDS);
