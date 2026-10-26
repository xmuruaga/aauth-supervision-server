# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this tracks an unsubmitted draft, every version also names the draft
revision it implements. The drafts are pinned to the AAuth repository at commit
`70d67375deb0bb002af7da0711fc58f6e8926e7e`.

## [Unreleased]

### Added

- **`param_in`, a rule that reads a code the resource states.** It maps parameter names
  to sets of strings and matches when each named parameter carries a value in its set,
  exactly (a list when any of its values does; an integer as its digits). It reads the
  parameters of a forwarded R3 proposal (`r3_member`), such as an offer's merchant
  category code, and of permission requests. A parameter that is absent or not a string
  or integer leaves the rule undecided, so `if_unknown` and the agent-data rules apply as
  for the other data rules.

## [0.2.0] - 2026-10-19: implements AAuth Supervision -00

### Fixed

- **A concurrent request could complete a composition the person never saw.** An act
  the SS had answered but that was not history yet (an `ask` the person was deciding, an
  open clarification, an `allow` whose `auth_token.issued` had not arrived) did not
  count, and Supervision L211 lets a request of the same chain arrive in between. Such
  an act now counts as uncertain: an `allow` (or an ask the person allowed) as able to
  take effect from that answer on, even before acts recorded since, an act still before
  the person or the agent from now on. It can turn a later act it composes with into an
  `ask`, never a `deny`, and it spends no budget. A
  person's earlier "no" to a composition that only an open act completes is put to them
  again, not applied. Every `allow` the SS sends for an auth token now carries an `exp`
  no later than an hour after the decision (this SS's choice: an allow may narrow `exp`,
  and the PS applies it to a token it issues, Supervision L508; an auth token lives at
  most an hour, Protocol L1775), and the allow stops counting once that cap and a
  60-second margin have passed, so a token the PS issues later is already spent. Its
  `auth_token.issued` is recorded with that `exp` (any `exp` from the decision to the
  cap is read as the cap applied), so the token reads as spent. Read as never expiring
  (the rule for any other `exp` not after the event's `iat`, the time of issuance,
  Supervision L198), it would deny honest acts for good. A token from an AS that does
  not accept the narrowed `exp` (L508 leaves that to the AS) may outlive the cap: once
  the cap and the margin have passed, it counts only when its `auth_token.issued`
  arrives. An ask the person allowed carries no cap and is awaited an hour from the
  answer. An `ask` counts until `decision.resolved` settles it or, in a mission, until
  the mission's `expires_at` plus the margin (Protocol L1425: the PS treats it as
  terminated and caps its tokens there). Open records are indexed, so the check does not
  walk every decision the SS has kept.
- **Concurrent allocations could together pass a resource ceiling or a class budget.**
  Allocations allowed but not yet reported issued were not counted, so several in a row
  could each fit. They still book nothing, but a later act that would take the ceiling
  or budget past its limit once they are issued, or may where an amount or a class is
  not known, is now put to the person (Budgets L903: per-token budgets SHOULD sum within
  the ceiling); it is never denied for them (`tests/test_open_acts.py`,
  `tests/test_budget_texts.py`).
- **One slow key server could hold a thread.** The fetch deadline covered the body
  only, so a JWKS host trickling its headers, or a resolver that never answered, held the
  request. One deadline now covers resolution, connect, TLS, headers and body, and a
  worker that finishes resolving or connecting after it sends no request. A worker that
  connected in time may already have sent its request when the deadline cuts it off.
- **Signatures, each now pinned by a test that quotes RFC 9421 or Signature-Key.**
  - A covered component with a parameter this verifier does not implement (`sf`, `key`,
    `bs`, `name`, `tr`), or `;req` on a request's own component, was read as if the
    parameter were absent; it now fails, as RFC 9421 Section 2.5 requires.
  - A non-Integer `expires` was ignored; it is a malformed parameter (RFC 9421
    Section 2.3) and now fails verification.
  - `Accept-Signature-Alg` listed quoted Strings; it is a List of Tokens
    (Signature-Key 4.2): `Ed25519, ES256`.
  - When the PS asked for a component the SS could not cover, the signed answer dropped
    every `;req` binding with it. It now keeps the components Supervision L340 says it
    SHOULD cover, and drops only what was asked beyond them (RFC 9421 Section 5.2).
- **A path the SS does not serve was answered `404` with `invalid_request`,** a code the
  Errors table pairs with 400 (Supervision L631). It is now HTTP's own 404 with an RFC
  9457 body and no AAuth code.
- **Spec conformance, each now pinned by a test that quotes the draft line.**
  - A consumption record for a live token freed the headroom it reported unspent. It
    now only raises an allocation's figure: a record "settles nothing" (Budgets L841)
    and the token "may spend more before it expires" (L465). The demo's fourth
    inference token is now put to the person.
  - A signature carrying an `alg` parameter that did not name the key's algorithm was
    refused; verifiers "MUST ignore it if present" (Protocol L2236).
  - An unknown `kid` could refetch a signer's JWKS every 30 seconds; the floor is now a
    minute (Protocol L2284).
  - A pending URL kept answering after its terminal response (the answer to a
    clarification reply, or a 408 `expired`); it now answers `410 Gone` (Protocol
    L2840). A retry of the request under its `sdi` still gets the same decision.
  - A throttled poll answered `rate_limited`; polling uses the protocol's polling codes
    (Supervision L639), so it is `slow_down` (Protocol L2626).
  - An unknown or used interaction code got a plain-text 404; it is now `invalid_code`,
    410 (Protocol L2396, L2625).
- **A token counts as usable for 60 seconds past its `exp`.** A resource judges `exp` by
  its own clock with no tolerance (Protocol L2317), so one whose clock runs a few
  seconds behind the SS's still accepts a token after the SS's clock has passed its
  `exp`. Sequences, which read a token's `exp` from this release on (see the next
  entry), treat a token as usable for 60 seconds past it (the default signature window,
  L2246). This margin is the SS's own choice, not a draft requirement.
- **A prohibited sequence could be composed by taking its tokens in reverse order.** The
  SS checked a sequence only when the act being decided was its last step. Because it
  decides when a token is issued, not when it is used, an agent could take the token for
  the last step first (allowed: nothing before it), then the earlier steps (allowed: "in
  the harmless order"), and use the last token after them. The SS now checks a sequence
  whichever of its steps the act is, treating each issued auth token as able to take
  effect at any moment until 60 seconds past its `exp` (the margin in the entry above).
  The `exp` comes from `auth_token.issued` and is kept with the history entry
  (`token_exp`); a token with no usable `exp` is treated as never expiring. Pairs were
  already checked in both directions and are unchanged. The search skips a sequence some
  step of which has too few acts, settles what a count check can before searching any
  order (as many distinct acts of a class must fit before each step's latest moment as
  the steps up to it need), and tries one act of several that are interchangeable: acts
  of a step that end at the same moment, and one-off acts of a step after the earliest
  that can still take it (an act that may also be of another class the sequence needs
  stands in for no other). It skips a placement of the act being decided that leaves
  later steps without a live token, and an order that cannot hold even if acts could
  repeat, and finds where each expired token's window ends by bisection, not by scanning
  every later entry. A search that exceeds its step budget is asked as unsettled, and no
  answer covers it. Checked against a brute-force oracle and an exhaustive enumeration
  (`tests/test_sequence_search_scale.py`).
- **A person's answer for one composition allowed an act that completed another.** When
  an act completed both a prohibited pair and a prohibited sequence, the SS named only
  the first, so a `mission` reach the person gave for `A then C` also let through
  `A then B then C`, which was never put to them. Every composition the act completes
  must now be covered by a reach before it allows; the first one not covered is asked
  (or denied), and a certain one is chosen over an uncertain one.
- **What the person read about a payment and a ceiling.** A payment whose operation
  and amount came from the resource's R3 proposal was put to the person as a high-impact
  act the supervisor had "no resource-asserted detail" of, because a static rule classed
  it. A proposal the resource bound into its resource token that names the act's
  operations or parameters is now the resource's word for the act whatever rule
  matched. A high-impact act the resource describes but no rule classes from that
  description is told so, and one whose class is assumed is told it may be of that
  class (`tests/test_ask_reasons.py`). Outside any mission, a resource ceiling was called
  a "mission ceiling", and an act the SS cannot account for was said to leave "the
  mission's spend" unknown; both name the acts outside missions
  (`tests/test_budgets.py`).
- **An assumed class composed only as itself.** An act whose class a rule's `if_unknown`
  assumed (data a rule needs is not available) composed only as the assumed class, never
  as the class it would have with that data: a mail send whose recipients are not known,
  assumed external, never took the internal-send step of a sequence, so the write that
  would complete one through it was allowed. It now composes as each such class too,
  uncertain, with the amount that class's rule reads, and so do a token replayed to a
  new SS, which carries no proposal, an act whose operations a data rule could not read
  where the rule that classed it names no operation, and a person token at a resource
  that serves on identity (as each class the policy gives the resource). The act's own
  assumed class counts with the most its rules read. A budget only such further classes
  reach is put to the person, never refused, even once it is spent, and the high-impact
  gate asks about a class the act only may have, even where the resource describes the
  act, telling the person it may be of that class; an act 0.1.x recorded keeps the one
  class it was booked with (`tests/test_ask_reasons.py`, `tests/test_replay_order.py`,
  `tests/test_agent_classes.py`, `tests/test_if_unknown_fallback.py`,
  `tests/test_identity_access.py`, `tests/test_snapshot_upgrade.py`,
  `tests/test_budget_texts.py`).
- **A `mission` reach given outside any mission held inside every mission.** An empty
  `mission_s256` on the reach was read as "any mission". It now holds only where it was
  given: outside missions.
- **A person's answer about a composition waived unrelated checks.** A reach given for
  `A then C` was also accepted by the intent and high-impact checks, so a later
  stand-alone high-impact act to the same target, completing no composition, was
  allowed without the person. A composition answer now covers only that composition,
  and a plain answer covers no composition.
- **Acts outside any mission did not compose with acts inside one.** History outside
  missions and each mission's history were separate, so reading inside a mission and
  sending outside it (or the reverse) was not seen as a composition. A decision now also
  sees the acts across the mission boundary of every agent of its chain (an agent acting
  under another agent's mission included), merged in the order the SS recorded them
  (history entries carry a record number, `n`, and the agent, persisted with the state;
  `tests/test_chain_member_boundary.py`). The agent's other missions compose as
  uncertain (see "A composition split across two missions" below), and class and
  resource budgets still count only the acts of the act's own mission (outside missions,
  the agent's acts outside missions). An act outside missions composes for certain with
  each mission separately, never with two missions as one history
  (`tests/test_mission_boundary.py`).
- **A permission grant counted as a single moment.** Core, Permission Response: the
  agent "MAY proceed with the action", at no stated time. A permission for the last step
  of a sequence, taken first, let the earlier steps through in the harmless order. A
  grant now counts as able to take effect at any later moment, like a token that never
  expires (`tests/test_history_timing.py`).
- **A permission the person granted while the SS could not answer was never recorded.**
  When the PS puts an act to the person because the SS is unavailable (Supervision
  L611), `decision.resolved` is the only record of a permission grant. It was ignored
  unless the SS's own record said `ask`, so a grant the SS had denied (its answer lost)
  or was still clarifying never joined history, and the acts after it did not compose
  with it. Such a grant now joins history; it still sets no reach
  (`tests/test_unavailable_supervisor.py`).
- **A budget or resource-budget ask hid a deny.** An amount the SS cannot see, or a
  resource token with no `budget`, was asked before the composition and count checks
  ran, so a certain prohibited composition or an exhausted count reached the person as a
  budget question. Every gate that denies now runs before any gate that asks, and an ask
  names the reasons from every gate that asks (`tests/test_ask_reasons.py`). A budget
  gate also asked about what it could not compare before it checked its own limit, so
  once a ceiling was spent, a request whose amount it could not compare (at a metered
  resource: no `budget`, one in another unit or scale, or an earlier act with no budget
  in the ceiling's unit; for a class budget by amount: an amount not visible) reached
  the person, whose "yes" would take a spent ceiling further. A spent ceiling now
  refuses such a request as exhausted (an act that may have the class only besides its
  own, assumed for data a rule needs, is still asked, and told the budget is spent);
  with room left, it is still asked, as an offer over the headroom is, and a "yes" lets
  that one act pass the ceiling (README "Limitations") (`tests/test_budgets.py`,
  `tests/test_budget_texts.py`).
- **A budget deny told the agent the person's ceiling.** A deny's `reason` goes to the
  agent (Supervision L265), and Budgets keeps the ceiling from it (L218: it "may not be
  shared with the agent"), but an exhausted or exceeded budget named its figures ("25.00
  USD of 25.00 USD committed", "at most 3 payment acts"). A deny now names the budget
  only ("Budget exhausted at https://inference.example."); the figures stay in the
  trace, and an ask, which goes to the person, keeps them (`tests/test_budget_texts.py`).
- **A grant of 0 was refused or asked.** An offer of 0 at a spent ceiling, with an
  earlier act there the SS cannot account for or with allocations still open, and an
  amount of 0 against a class budget already passed, was refused or put to the person,
  though such a grant spends nothing (Budgets L344, L913). An offer of 0 in the
  ceiling's unit and scale, and an amount of 0, now fit (a class budget's count still
  applies) (`tests/test_budget_texts.py`).
- **What an ask offered and what the SS applied differed.** A budget ask offered
  `mission` and `always`, which the SS never applied to the budget but did apply to the
  intent and high-impact checks of later acts; a composition ask outside any mission
  offered a `mission` reach that nothing would end. A budget ask now offers this act
  only, a composition ask outside missions offers this act only, a composition label
  names the target the answer is keyed on, and an ask with no `apply_options` (in 0.1.x,
  the clarification round limit's, a mission proposal's, a mission update's and any ask
  a pluggable policy returned without them; now only an ask about an act for which a
  pluggable policy names no reach, as every other ask names its reaches, the round
  limit's, a proposal's and an update's included) honours the fixed `once`, `mission`
  and `always` of Supervision L599 instead of reducing them to `once`
  (`tests/test_ask_reasons.py`, `tests/test_reach_fixed_options.py`).
- **A `deny` the person gave a reach was forgotten.** Supervision L582: the SS remembers
  and applies the person's answer. A `deny` with `mission` or `always` is now applied
  where the SS would otherwise ask again, and an `always` answer replaces the `mission`
  answers for the same kind and composition (Supervision L603: "until the person
  changes it") (`tests/test_reach_deny.py`).
- **A permission named like a resource was classified and answered as that resource.**
  A rule's `resource` was matched against a permission's `action`, which the agent
  chooses, and both shared one reach key. A rule's resource now matches resources only,
  and such a permission has its own key (`tests/test_ask_reasons.py`).
- **A disconnect left what was open for the person working.** A clarification URL
  still answered, and could record an allow, for a person who had disconnected; a
  connect awaiting confirmation could still be confirmed, and its poll still said
  "connected" (Supervision L188, L249). A disconnect now abandons the clarification and
  ends the connect, and a mission is used only by requests naming its own person; a
  request at the abandoned clarification's pending URL gets `unknown_sub`, so the PS
  connects and resends (L249, L633) (`tests/test_connection_scope.py`).
- **Timing in history.** A late `audit.recorded` was placed at its report, after acts
  that followed the action; a second `auth_token.issued` under one decision replaced its
  allocation; a token replayed after a routing change was placed after the entries it
  may have preceded. Another token under one decision (another `jti`) is now another
  act, with its own allocation, and a replayed token, a person token reported with no
  decision on record and a token an approval issued are taken as usable from the start
  of the history (an approval's token, booked at approval or reported before or after
  it, from the SS's answer to its proposal, however promptly the approval was reported),
  in every copy of them a composition reads (`tests/test_history_timing.py`,
  `tests/test_issuance_events.py`, `tests/test_replay_order.py`). A token, or a
  permission the person granted, whose report arrives after an act recorded since its
  decision (its person's answer, for an ask) that the PS stamped later (out of the order
  L211 asks for) floats: it may have been used at any moment from the first act since
  that decision that the PS stamped no earlier (those recorded before it came first),
  and surely before every act it was stamped before; a person's answer reported so
  floors its token at the question. In the same second, which came first is not settled:
  a completion that needs the act first is asked each time, this act only, and no answer
  covers it. Acts are ordered by the PS's stamps (`iat`, kept on each entry), never
  against the SS's clock (0.1.x kept, for an act it decided, only the SS's time of the
  decision: see State); against a token's end, which is on the SS's clock, an act is
  placed for certain no later than its stamp moved by the offset its report's signature
  shows (`created` against the report's arrival), plus 2 seconds for whole-second stamps
  and signatures, and possibly as early as its stamp less the most the PS's requests for
  connected people have shown its clocks ahead (their stamp or signature against their
  arrival, a stamp past the window not read; kept by PS), less a second and the server's
  `transit_allowance` (2 s by default, for the fastest of those transits), so a PS clock
  behind or ahead neither stretches nor shortens a token's life, however slow any one
  report is (a clock that moves back is read at its earlier lead, for as long as the
  state is kept: more asks); an act reported more than 5 minutes after its stamp, or an
  auth token replayed to a new SS, is placed anywhere the signature window allows around
  its stamp. An approval's person token lives to the `exp` the PS writes on it, an hour
  from the approval's stamp. An audited action in the second of a pinned act recorded
  before it is not taken for certain after that act. A permission the SS grants itself
  is placed by its request's stamp or signature (`created`), whichever is later (a
  retried request keeps its first `iat`, L198). An audited action reported late is not
  taken for certain after acts stamped after it. A token whose place is not known
  reaches, before it expired, the earliest place of every such token stamped before its
  end. An audited action may have taken place before every entry, as such a token may.
  Where such a token stood is not known, so it makes a composition certain (a deny) only
  from where its stamp places it: after every act pinned at its place (one that does not
  float, not an audit record) stamped no later than it, every audit record stamped no
  later, and every such token stamped earlier; until just after the last pinned act
  stamped a whole second before its end, and the place of every such token issued while
  it was surely live (any token reaches that place for certain, one reported where it
  stands too: a completion that needs it after the late token is denied, where it was
  asked). One that may have ended before the first pinned act stamped after it acts
  there only, if it ended after the latest its own stamp can be on the SS's clock and no
  act stamped after it stands before that place. Where certain acts complete a sequence
  only once such tokens float, the stamps settle it neither way: it is asked, and no
  answer about a sequence that only "may" complete covers it, and it offers no reach
  beyond this act; it says the order, or whether a token was still live, is not settled
  (or would take more work to settle than the SS allows). A replayed token whose stamp
  is after every pinned entry before it and before every pinned entry after it stands
  where it arrives, so a mission's log replayed in order is judged as it was recorded,
  except near a token's end: a replayed token stamped within about a minute of that end
  may stand on either side of it, being placed anywhere the signature window allows
  around its stamp, so a completion that turns on which side is asked. An answer given
  about a "may" never covers what may be certain. A token reported late never stands for
  certain before an act the SS recorded before the answer that allowed it (`after_n`),
  so a PS clock stepped back cannot make a false deny; where that floor is past where
  its stamp places it, it takes no step for certain. An approval's token stays open
  until `approved` books it, for as long as it could be live (an hour to issue it after
  the answer, an hour of life).
- **The budget ledger.** An act whose amount the SS never saw was booked as 0 against a
  class budget by amount; a stale or other-scale consumption record was applied; an
  amount of thousands of digits made the request fail; the range bound was 2^53 instead
  of Budgets' 15 digits (`tests/test_budget_ledger.py`).
- **State.** A snapshot written by 0.1.x is migrated (see Changed): its entries are
  numbered in the order a decision reads them, every act but an audit record floats (0.1.x
  judged no report late), a decision with no recorded place counts from the start, and an
  answer with no recorded time as given at the upgrade. 0.1.x kept, for an act it
  decided, only the SS's time of the decision (for an audit record or a replayed token,
  the PS's stamp): with the PS clock behind, a token it decided whose issuance is
  reported after the upgrade can be taken as reported late, and a completion that needs
  it before an act 0.1.x recorded is then asked each time. A body nested deeply enough,
  once stored, made every later snapshot write fail; a lone surrogate in the agent's
  text made a deny a server error; a second clarification round refused the PS's retry
  of the original request; `--state` in a missing directory failed every request; the
  snapshot was not written through to disk, and a Windows sharing violation failed the
  request (`tests/test_snapshot_upgrade.py`, `tests/test_state_robustness.py`,
  `tests/test_state_persistence.py`).
- **Key discovery and transport.** A signer the SS does not accept made it fetch two
  documents and cache them without bound; a request naming a made-up `kid` while the PS
  host was briefly down locked the PS out (core L2284: use the cached JWKS when a fetch
  fails); malformed key material was a server error; a body naming a member twice was
  accepted; a NAT64 or IPv4-compatible address embedding a private IPv4 passed egress; a
  non-ASCII Content-Length dropped the connection; an obs-fold collapsed other
  whitespace; an uncovered query was a 400 instead of `invalid_input`
  (`tests/test_key_discovery_admission.py`, `tests/test_transport_details.py`).
- **Bounds.** The resolver's record of fetch attempts is bounded like its cache, and
  records only fetches actually made; a body nested past the JSON decoder's own limit is
  `invalid_request`, not a server error (`tests/test_key_discovery_admission.py`,
  `tests/test_state_robustness.py`).
- **A malformed mission blob could set aside every PS's state.** A blob that was not a
  JSON object was stored: every later decision on an act in the mission, until it was
  terminated, was `server_error`, and the snapshot was unreadable at the next start, so
  the SS set aside all of its state. An `approved_tools` or `approved_resources` that was
  not an array was stored too: a number, `true`, `false` or `null` made every later
  decision that read it `server_error`, and a string or object was misread (a resource
  whose identifier is a substring of an `approved_resources` string counted as
  approved). Either blob is now `invalid_request` (Protocol, Mission Approval). Accepted
  mission updates are kept beside the blob instead of written into it: its members are
  the PS's (Protocol L1429) (`tests/test_state_robustness.py`).
- **Hostile values the body check did not reach.** A forwarded token, or R3 bytes, nested
  past the JSON decoder's own limit; a `decision.resolved` `iat` past the float range,
  which failed after marking the ask resolved; and a `param_gt` parameter past the float
  range were each `server_error`. They are now `invalid_request` (a parameter: not
  visible), and an `iat` or `exp` past the integers JSON parsers hold exactly (I-JSON,
  RFC 7493 Section 2.2) is refused before anything changes
  (`tests/test_state_robustness.py`).
- **An `exp` with a fraction lost the issuance.** A JWT NumericDate may have one (RFC 7519
  Section 2). `auth_token.issued` with such an `exp` was `invalid_request`, which the PS
  does not retry (Supervision L631), so the issued token stopped composing once its allow
  left the open window. It is read rounded up (`tests/test_issuance_events.py`).
- **An `iat` with a fraction or an exponent lost the act.** Supervision L198 gives `iat`
  as "seconds since the epoch" and says no more. A request or event whose `iat` was
  written with a fraction or an exponent (`1790600000.5`, `1.7906e9`, even
  `1790600000.0`) was `invalid_request`, which the PS does not retry (L631). Such a
  request was put to the person without the SS (L611). Such an event was never
  recorded, so later acts that compose with its act were judged without it. Under
  `examples/policy.json`, an external send audited so, then a read of sensitive records,
  had the read allowed. Any JSON number of at most 2**53 - 1 either way is now accepted,
  read as the whole second it falls in, and kept as an integer (see Changed)
  (`tests/test_iat_seconds.py`, `tests/test_conformance.py`).
- **The SS read a forwarded resource token without checking its `typ`.** Protocol L2896:
  implementations "MUST check `typ` before acting on any AAuth JWT". A `resource_token`
  whose header is not `aa-resource+jwt` (compared as RFC 7515 Section 4.1.9 compares a
  media type) is now `invalid_request` (`tests/test_conformance.py`).
- **A permission `allow` carried `exp`.** Supervision defines `exp` on the allow of a
  person token (L485) or an auth token (L508); a permission becomes `granted` (L531),
  which has no lifetime. A permission allow now carries no `exp`
  (`tests/test_conformance.py`).
- **The access log kept the interaction code.** It logged the request line, query
  included, so `/interaction?code=...` wrote the code to the operator's log. The line now
  leaves the query out (it keeps the client address, method, path, HTTP version and
  status), and a request line too malformed to have a path still gets its 400
  (`tests/test_server_cli.py`).
- **The access log wrote control characters as received.** Its `log_message` replaced the
  standard library's, which escapes them, so a request line carrying ESC sequences could
  clear or retitle the terminal showing the log, or forge a line in it. C0 and C1
  controls are written as `\xNN`, as the standard library writes them, and a backslash
  the client sent is doubled (`tests/test_server_cli.py`).
- **A recipient list in one parameter hid an external address.** The domain rule
  (`param_domain_not_in`) read only the domain after a value's last `@`, so after a
  sensitive export `"to": "drop@evil.example, team@corp.example"` was an internal send,
  and allowed; so was a percent-routed or quoted local part. A recipient in `cc` or `bcc`
  was not seen either: a rule naming them made every mail without them unknown. Each
  recipient a value names is now read: one with no `@` is still read as a domain itself,
  and any other that is not plainly `local@domain` (or `Name <local@domain>`) is outside
  every listed domain. Every parameter a rule names is read, and one the act does not
  carry names nobody; with none of them present the recipients are unknown, as before.
  The example policy names `to`, `cc` and `bcc` (`tests/test_recipient_domains.py`,
  `tests/test_policy_semantics.py`).
- **Agent text was Markdown in what the person sees.** An ask's `summary` and each
  `apply_options` label are Markdown the PS shows the person (Supervision L266, L584).
  The agent's justification, a tool name, the tools of a mission proposal, a mission
  update and an advisor's rationale in `examples/layered_policy.py` were put there as
  written, so an agent could add an image the PS would load (carrying what the agent had
  read), a link, HTML, or a line that read as the supervisor's own verdict, where the
  core requires agent-asserted content to be attributed to the agent (Protocol
  L1037-L1039). Agent words are now quoted in a code span or a fenced block that nothing
  inside can close, with control and format characters removed and a length cap, and a
  resource's budget unit is quoted in a code span too, unless it is a short word of
  ASCII letters (`EUR`, `tokens`). Combining marks are kept to four on one visible
  character, whatever characters drawn as nothing separate them, and a proposal's ask
  says what it asks before it names at most twenty tools, each cut to 64 characters
  (`tests/test_person_facing_text.py`, `tests/test_markdown.py`,
  `tests/test_properties_markdown.py`).
- **A PS `id` that is not a server identifier was accepted.** Under open registration a
  signer named by a path or a port of a shared host (`https://host.example/~mallory`), or
  in upper case, reached connect as a PS of its own. A PS signs with its `issuer` as `id`
  (Protocol L2187), a server identifier (L1948-L1969): any other `id` is now
  `invalid_key` before any fetch, and a `trusted_ps` entry must be one too
  (`tests/test_key_discovery_admission.py`).
- **A composition split across two missions was allowed.** This SS approves a mission
  proposal by policy and allows every completion, so an agent could read in one mission
  and send in a second, and the person was never asked; a token from the first mission
  is still usable then. The acts of the agent's other missions (of the same person,
  owned or acted in by an agent of its chain) now compose as uncertain: such a
  composition is put to the person, never denied by the SS on its own, and a "no" the
  person gave to it with reach is applied (Supervision L582). Class and resource budgets
  stay per mission.
  A decision on an act in a mission composes the acts of the other missions once, all
  together, so its cost grows with the history, not with how many missions it is split
  across. For an act outside missions, each mission its agent owns or has acted in that
  holds a certain act of a class in a composition still short of certain is also
  composed on its own with the certain acts outside missions; that work is capped at
  twice the history's length in entries composed, never below 20,000, each pass counting
  100 more, and past the cap what is still short of certain is unsettled and asked. A
  test checks that 4,000 acts over 400 missions cost at most three times the same acts
  in one mission, plus 50 ms, for an act in a mission and for one outside, and another
  that with 200 missions a decision on 2,000 acts outside missions does at most twenty
  times the work it does with none. The answer is checked against the plain per-mission
  computation, and a model-based test checks every answer with missions and person
  tokens in play (`tests/test_cross_mission.py`, `tests/test_mission_boundary.py`,
  `tests/test_cross_mission_scale.py`, `tests/test_properties_cross_mission.py`).
- **A composition split between two instances of one agent was allowed.** Every
  instance has its own identifier (Protocol L167), and the SS composed per agent and
  call chain, so after one instance exported customer records a second instance of the
  same provider could send them with no one asked. The acts of the person's other
  agents from the provider of an agent in the act's chain (`aauth:local@domain` names it,
  L488), outside missions and in their missions, now compose as uncertain, as another
  mission's do: asked, never denied, spending no budget. Agents of other providers do
  not compose. The person's agents are found through an index of the agent keys, so a
  decision does not read every person's (`tests/test_agent_provider.py`;
  `tests/test_properties_cross_mission.py` now drives two instances, each acting in its
  own missions, in the other's and outside missions).
- **A read on a person token alone never composed.** A resource may serve on a person
  token with no auth token (Protocol, Person Identity Access), and `person_token.issued`
  changed nothing. A policy now lists the resources that serve on identity
  (`serves_on_identity`; the example lists `https://records.example`); a person token
  for one joins history as an uncertain act of the resource's class, usable until its
  `exp`, spending no budget (`tests/test_identity_access.py`). An ask that a composition
  may rest on such a token names the resource it was issued for
  (`tests/test_ask_reasons.py`). A `person_token.issued` for a person token whose
  decision is on record needs no `aud`, since the decision says where the token goes;
  an identity check books nothing. A decision on a person token for such a resource is
  the act it can be: the most severe class the policy gives the resource, uncertain,
  through the high-impact gate, open until reported issued, and recorded
  (`tests/test_identity_decisions.py`).
- **Approving a mission issued person tokens no one decided.** The PS issues a person
  token at approval for each approved resource (Supervision L417, L420; Protocol L1415),
  whoever approved, and at a resource that serves on identity that token is access. Each
  is now decided as a `person_token` decision would be, on an `allow` and on an `ask`
  alike (the person may approve the refinement put to them): in turn, since they are
  issued together, each one allowed counting for the next; and with only `always`
  answers applied, since the token carries a mission that does not exist yet. One the
  policy would not allow outright is named in the ask and left out of the refinement;
  one it allows is an open act until the mission is approved. The tokens are issued at
  approval, from what the person approved (Supervision L422: they may edit the
  refinement), and a person token lives an hour at most, not past the mission's
  `expires_at` (Protocol L863). So the first `approved` report of a mission books one in
  the mission for each resource it names that serves on identity (past 256, one for each
  kind of act, its class and the others it may have: they share one window), as an act
  of the approval usable for that hour, what a reported person token is; a PS may
  decline to issue one (Protocol L1415), which no event says, so it is booked all the
  same. `person_token.issued` refines it, in its mission (it carries the mission's
  `s256`) whatever the report names, matched by the mission or the proposal's `sdi`: the
  `approved` report that names it links the proposal to its mission (Supervision L443),
  and one reported before it is an open act until that report books it in that mission,
  not in another of the agent's. Where any of these tokens stood among the person's acts
  is not worked out from when the approval or a report arrived: each is taken as usable
  from the moment the SS answered the proposal (never before an act the SS had recorded
  by then), so it can make later acts be asked, with no end in time, never allowed for
  want of an order (in a mission, a `mission` reach the person gives covers that
  composition for the agent's later acts of the same class on the same target that may
  complete it; outside missions each such act is asked); one open before `approved`
  floats too, and it stays open while its proposal awaits the person's answer, however
  long. Two tokens reported for one resource under different `jti`s are both kept, each
  one act however often it is reported (one held before `approved`, from its first
  report to its latest `exp`). Reports that name no `jti` cannot be told apart, from
  each other or from the approval's token: they may be taken as one act, or each booked
  as an act of its own. An `approved` that names no `sdi` links no proposal (none is
  guessed): its tokens are booked from its blob, and a report under the proposal's `sdi`
  is held, then booked outside missions past its `exp`, where nothing places it: a
  sequence through it may complete with any later act, so the agent's later acts that
  could complete one are asked. Naming the `sdi` books the report as the approval's
  token instead of a second act outside missions. One of a resource the mission does not
  name, or of a proposal declined or abandoned and never approved, is not booked unless
  reported (a reported token is a fact: under a declined proposal, or past its `exp`
  with no approval to book it, it is booked outside missions, before the decision that
  finds it so composes); an open one is no allocation at a metered resource. The SS
  keeps its own records of these tokens under keys no sdi a PS mints can name, and marks
  the act it books at approval by its detail, not by an sdi. A resource named twice is
  one token, at most 16 are decided for one proposal (the rest are put to the person),
  and a proposal names at most 256 resources and 256 tools
  (`tests/test_approval_person_tokens.py`).
- **A composition answer's label read "Allow ...".** The SS remembers a `deny` with the
  same reach (L582), so the label names what the answer reaches, not the answer
  (`tests/test_ask_reasons.py`).
- **Composition and classification.**
  - A replay to a new SS kept one token per decision: two `auth_token.issued` under one
    `sdi` (two tokens issued for one decision) were deduplicated on the `sdi`, and the
    second token was lost. Replay now tells tokens apart by `aud` and
    `jti`, and each keeps its own `exp` (`tests/test_replay_tokens.py`).
  - Open acts (an ask the person is deciding, an allow not yet reported issued) count
    wherever a recorded act would, in another mission or at another instance of the
    provider too, always as uncertain (`tests/test_composition_scope.py`,
    `tests/test_open_acts.py`). The scope an act composes over is also found as if
    every open act were history, and what that adds composes as uncertain: an open act
    links an agent to a mission, brings in that mission's agents' acts outside missions
    and the instances of their providers, wherever the same act recorded would, and
    recording it never narrows the scope (`tests/test_open_chain_links.py`). An act
    whose window is over, or whose mission has ended, links nothing: every record
    settled for good leaves the open set before the scope is found, so a decision does
    not depend on which earlier decisions looked at it, nor on a restart. Open acts are
    taken in the order they were recorded, not in an order that changed from one process
    to the next, nor across a restart (`tests/test_store_indexes.py`).
  - A forwarded proposal for another operation than the one a data rule is narrowed to
    let a later rule decide the act as certain. The data the policy needs is still
    unknown, so the act takes the rule's `if_unknown`, uncertain; the example policy has
    a catch-all mail rule. Where the rule reached names no operation (a scope rule, as for
    a `mail.read` token whose proposal names `reply_email`) and has no `if_unknown`, the
    act takes the most severe class of the data rules that could not read it, uncertain,
    where that class is more severe than the rule's
    (`tests/test_if_unknown_fallback.py`).
  - Two agents of one call chain acting outside missions did not compose; outside
    missions an act now composes with the outside acts of every agent of its chain
    (`tests/test_composition_scope.py`).
  - A `result` the rule could not read counted as nothing sensitive, on certain
    evidence; it now counts as not visible.
  - Agent-asserted data that raised an act's class could take it out of a prohibited
    pair (a send the agent calls bulk, a class in no pair), out of that class's budget,
    and out of the high-impact gate. Such an act is also each class the rules give it as
    each data rule its data decided is set aside in turn (the agent's data still read),
    down to the rule that closes the scan, each held to the class it has with the data
    unknown and with its own certainty: it composes as each, counts against each one's
    budget with the amount that class's rule reads, and meets the high-impact gate if
    any of them is high impact, as the act decided and as an earlier act in history
    (`tests/test_agent_tightening.py`, `tests/test_agent_classes.py`). It is one act
    under all of them: it takes one step of a sequence, never two, and it is certain
    under a class only where that class is and the act itself is (an act of another
    agent or one not settled yet is uncertain under each). Data that would lower a class
    leaves the act the class it has with the data unknown, as certain as that class is
    (it made a certain class uncertain, an ask where a deny was due). Each class counts
    the largest amount any rule giving it reads (a payment counted as its fee, or as an
    amount not visible where the payment rule read it). A "may" names what could
    complete it, where each act is and what it is, an agent linked by an act not settled
    yet included (`tests/test_blind_alias.py`, `tests/test_open_chain_links.py`).
  - An `allow` with reach given when a composition was only possible covered a later
    certain completion (with `composition_on_certain: deny`, one the policy denies
    outright); the person was asked about "may", never "would". It no longer does. A
    `deny` with reach is applied wherever recorded acts complete the composition, in
    another mission or at another instance too, through either class of an act the
    agent's data raised (`tests/test_reach_answers.py`,
    `tests/test_agent_tightening.py`). An answer to one plain gate (outside the mission,
    or high impact without resource-asserted detail) covered the other, which the person
    was never asked; each gate now reads its own answer, and one kept by an earlier
    version covers neither, so the person is asked again (`tests/test_plain_gates.py`).
  - A tool name with an invisible character or edge spaces matched no rule while reading,
    to the person, as the name it imitates; such a name is refused: a control, format or
    default-ignorable character (Unicode 15.1), an unassigned code point, a space other
    than U+0020, or the Braille blank (`tests/test_tool_names.py`).
  - `examples/layered_policy.py` showed the advisor's verdict on an ask the floor kept,
    so a model's words read as the reason; the advisor's view is shown when it asks.
- **Decisions the PS can act on.** A pluggable policy that answered `clarify` after the
  rounds were spent, or a value the protocol does not define, produced a 200 with that
  value; a decision is `allow`, `deny` or `ask` (Supervision L262), so the act now goes
  to the person (`tests/test_clarification_rounds.py`). An update or a completion of a
  mission past its `expires_at` was allowed; it is denied, as any act in it is (Protocol
  L1425; `tests/test_mission_expiry.py`). An update the person allowed after an ask was
  not kept with the mission; it is (`tests/test_mission_updates.py`). A pluggable
  policy's `allow` of a proposal went
  out without the REQUIRED `description` (L415), and its narrowing could overwrite the
  answer's `sdi` and `decision`; the proposal's description is sent, and the answer's own
  members win (`tests/test_pluggable_policy.py`).
- **The wire.** A reused connect `id` was answered from the state whatever its `action`
  (an unrecognized one got 200, a `disconnect` under a connect's id did nothing); the id
  names its action and is refused under the other (L238, L631;
  `tests/test_connect_ids.py`). A connect awaiting the person never said `interacting`;
  it does once the person opens the page with its code, and still does after a restart
  (Protocol L2523; `tests/test_connect_interacting.py`, `tests/test_state_bounds.py`). A
  PS that replaced its key under the same `kid` was refused until the cache expired; a
  cached key that fails is refreshed once, within the once-a-minute floor, before the
  request is refused (Protocol L2286; `tests/test_rekey_same_kid.py`). A connect
  awaiting confirmation, and its code, now expire after an hour: presenting the code
  then fails with `expired` (Protocol L2400; `tests/test_connect_lifetime.py`). The
  `Server` header ended in a space; it is `aauth-ss`. On CPython 3.13.16, 3.14.8 and
  later, a request line with no version (HTTP/0.9) reached the handler with no header
  block, and the connection dropped with no answer; it is a 400 with a status line on
  every version (`tests/test_listener_http.py`).
- **Work under the store lock, and growth.** A decision outside missions skips the
  per-mission passes that cannot add certainty (`tests/test_composition_cost.py`). Open
  decisions, missions, pending records and reach answers are indexed by person, code and
  `sdi`, so a decision does not walk every person's state, and records that can no
  longer be open leave the index (`tests/test_store_indexes.py`,
  `tests/test_reach_by_person.py`). Writing the snapshot does walk it, under the lock:
  every signed request answered with no error code wrote it, polls, repeats and the
  bodiless `410` at a withdrawn pending URL included, and none refused with an error
  code did, even one that followed a change (the 408 `expired` below); a request that
  changed nothing no longer writes it, and a refusal is written only when it follows a
  change (a question past its deadline) (`tests/test_snapshot_writes.py`,
  `tests/test_state_bounds.py`; see README, Limitations). After a write that failed,
  every request writes until one succeeds, so a retry answered from memory does not
  leave a change off disk. Text is bounded by the size it is kept at (JSON, every
  character past ASCII escaped, so the bound is smaller in characters for other
  scripts): a `description` or a `reason` at most 64 KiB, a proposal's `tools` 128 KiB,
  an approved mission blob 512 KiB. A mission blob, kept parsed and copied on every
  write, holds at most 10,000 JSON values, and a proposal's `tools` (echoed whole in the
  mission it approves) 9,488, so the blob of any proposal the SS allows fits. A tool
  name is bounded at 256 characters, `agent_iss` and `agent_sub` at 512, and a token's
  scope and a proposal's operations at 256 entries. A refused issuance report books
  nothing. A settled clarification keeps no request body, one past its deadline is
  settled when the person's next question is counted
  (`tests/test_expired_clarifications.py`), and a person has at most 100 open
  clarifications. An issued token's `aud` array names at most 64 audiences and is
  matched against the history in one pass (`tests/test_audience_bounds.py`). Identifiers
  the SS keeps (`sub`, `sdi`, `id`, `agent`, `tenant`, `jti`) are at most 512
  characters, and a signer only open registration admits holds at most 64 connects
  awaiting confirmation (one the person answered counts no more), each removed with its
  `id` a lifetime after it expires; it keeps no other id, and its PS name is kept as the
  page shows it, plain and cut. All such signers together hold at most 1,024; at that
  cap the oldest record of the domain holding the most makes room for another, so that
  no group of names keeps the others out. At that cap the names made under one domain
  count as one, since a wildcard DNS entry makes any number of them: a domain is the
  host's last two labels, or one label more under a listed public suffix (a country's
  second level such as `co.uk`, a hosting service such as `github.io`, whose sites are
  each their own). A connect failed by five wrong operator tokens still counts until its
  record goes (`tests/test_connect_lifetime.py`, `tests/test_state_bounds.py`).
  Signature fields are bounded before they are parsed, the rate table, once it holds
  more than 4,096 signers, drops those idle for a minute, and the listener queues a
  burst instead of refusing it (`tests/test_bounded_work.py`). A poll or retry of a
  clarification restated the full `timeout` while its deadline stayed fixed, so an
  answer within the time a poll stated could arrive after the deadline enforced (a 408
  `expired`); it now states the time left, rounded down so that it is never later than
  that deadline (Protocol L1071; `tests/test_bounded_work.py`).
- **Key discovery.** A `jwks_uri` with a port out of range or an unbalanced bracket, or
  a host label longer than DNS allows, was a 500; it is `invalid_key`
  (`tests/test_resolver_hardening.py`). During an outage every request fetched again; a
  signer's keys are now fetched at most once a minute, less often the longer the outage
  lasts (up to an hour) while it stays in the cache, the keys held are served meanwhile,
  and a signer with none is refused without a new fetch (Protocol L2284). Requests for
  one signer that arrive together make one fetch. The cache was shared by request
  threads without a lock (a 500 under load); it is locked, never evicts a trusted PS,
  and evicts first a name whose JWKS was never requested, then, of the signers whose
  fetch floor has passed, one that holds no keys before one that does (each the least
  recently used), then, within their floors, one that holds no keys before one that
  does (each the least recently used); one evicted within its floor is not
  fetched again within its minute and keeps the keys it held, and takes its place again
  when it returns. The signers of one domain (as at the open-registration cap) hold at
  most 64 entries and the floors of names that were reached together (the floors of
  names never reached are bounded by the floor table), so names made under one domain
  churn only that share; in it a name whose JWKS was never requested (one nobody serves
  documents for) gives way first, so names made up under an honest signer's domain do
  not push it out (a name being fetched, or never tried, is not taken for one), and one
  pushed out within its wait keeps its floor while the table of floors has room. A
  signer pushed out of the cache past its wait starts its backoff over: it is never
  fetched more than once a minute, but less often only while it stays in the cache. When
  four times as many floors are kept as the table holds, the floor of a signer whose
  JWKS was never requested (a made-up one) gives way, and with none a new signer is
  refused rather than a floor forgotten. Of a signer's documents only the first 32 keys
  are kept, at most 16 KiB of them, each with the members a key is found and read by
  (others are ignored, RFC 7517 Section 4; a key published with private material is
  refused when used, as before), and the metadata's `issuer`, `jwks_uri` and `name`
  (`tests/test_resolver_hardening.py`). An Ed25519 key of small order, or not
  canonically encoded, and an ES256 coordinate that is not 32 octets or a point off the
  curve are refused (`tests/test_key_and_digest_edges.py`). A Content-Digest that names
  one algorithm twice is refused.
- **The listener.** A header line with whitespace before its colon, or with no colon,
  made the standard library drop the fields after it, Content-Length included, so the
  body was read as the next request; a folded line was kept with its line break inside
  the field value. Such a request is a 400 and the connection closes
  (RFC 9112 5.1, 5.2). An absolute-form target's authority is the one the request is
  for (RFC 9112 3.2.2); a target `urllib` cannot read got no reply and now gets a 400;
  an HTTP/1.1 request with no Host is a 400 (RFC 9112 3.2). Every refusal of the
  listener, its own and the standard library's, is `application/problem+json` with an
  `error` member, and none repeats the request line (which can carry an interaction
  code). Method names are case-sensitive (RFC 9110 9.1): a method the SS implements that
  a resource does not take is a 405 naming those it does, one it implements nowhere a
  501, and HEAD is served (`tests/test_listener_http.py`). A request must arrive within
  10 seconds whole, however slowly its bytes come, and at most 64 connections are served
  at once, the next waiting in the listen queue; while all are taken, each answer closes
  its connection (`tests/test_listener_limits.py`). An
  unexpected failure is logged with its traceback for the operator, and an authority
  error no longer repeats what the client sent.
- **Persistence and the process.** On Windows a second SS bound the port of the first
  and took over its state when it exited; the port is bound for exclusive use, and
  `aauth-ss serve` holds its state file (`tests/test_single_instance.py`). A state file
  named `*.tmp` was its own temporary file, and the snapshot write is retried for a few
  seconds when another process holds the file. The state file is held before it is
  read, and two snapshots set aside in one second are both kept. A `--state` that
  is a symbolic link was replaced by a regular file; it is written and held where it
  points (`tests/test_serve_startup.py`).
- **The command line.** A file nested past the JSON reader's depth showed a traceback.
  `keygen --force` wrote into the existing file, keeping its mode, and followed a link
  at `--out`; it writes a new file, owner-only on POSIX, that replaces what is there
  (`tests/test_keygen_file.py`). A `kid` with a quote or a backslash broke every signed
  answer and one outside printable ASCII could not be sent; the first is escaped, the
  second refused (`tests/test_signing_kid.py`). The confirmation page refuses a form
  post from another site before it counts against a connect, and takes its own form
  when opened on the loopback listener (`tests/test_interaction_origin.py`); it shows
  the code first and the PS's self-asserted name as plain text, cut to 64 characters
  (`tests/test_interaction_page.py`). `serve` on a port in use, a port out of range, a
  state path that is a directory, and `keygen` into a path it cannot create showed a
  traceback; a port out of range is now a usage error (the usage, then one error line,
  exit 2), the others one `error:` line and an exit status, and `--host ::1` binds
  (`tests/test_serve_startup.py`). `explain` decided a resource the SS refuses; it says
  it is not a server identifier (`tests/test_explain_resource.py`).
- **Configuration.** `check-policy` passed resource patterns that can never match a
  server identifier (a label starting or ending with a hyphen, an empty label, an
  unclosed bracket among them) and `param_gt` thresholds of NaN, infinity or an integer
  past the float range; the loader refuses them: the pattern is walked against the
  identifier grammar, so it accepts every pattern that can match one, but for label
  lengths: the first match the search finds may have a label past 63 characters, as
  for `https://` and 64 `?`, and the pattern is refused although a match with a dot in it
  would do. A `max_mission_seconds`
  past ten years made every proposal a 500, and a
  ceiling's `decimals` had no bound; both are bounded, and a ceiling's `max_amount` has
  at most 15 digits (Budgets L326; `tests/test_policy_loader.py`). `egress.timeout` and
  `egress.max_bytes` are checked numbers in range, and `documentation_uri` must be an
  https URL a reader can follow (Protocol L1994; `tests/test_published_urls.py`). A
  mission's `expires_at` with a lower-case `t` or `z`, or a leap second, read as expired
  (RFC 3339 Sections 5.6, 5.7; `tests/test_rfc3339_times.py`). The example policy names
  the read operations of its mail resource, so a `mail.read` proposal for one is no
  assumed send.
- **The demo** said a per-call SS would have allowed both acts of the split
  exfiltration; on the -00 wire it asks too (high impact, no resource detail). The demo
  says what the composition adds: the read the send may complete.
- **The confirmation page could be locked for everyone.** Five wrong operator tokens, from
  anyone, refused every confirmation until a restart. A wrong token now counts against
  the connect whose code it was posted with: after five, that connect fails for good (its
  code `invalid_code`, as Protocol L2398 has for code attempts; its PS told `denied`), and
  a post with no live code
  is refused as such and never counts. The count is kept with the connect's record: it
  goes when the record goes, and is saved by the next write (the fifth wrong token,
  which fails the connect, is written at once) (`tests/test_service_edges.py`,
  `tests/test_interaction_origin.py`).
- **A mission proposal or update put to the person let the PS offer reaches the SS never
  applied.** Such an ask carried no `apply_options`, so the PS could offer `mission` and
  `always`, whose meaning is fixed (Supervision L599), while the SS keeps no reach for a
  proposal or an update. It now offers only "This proposal only" or "This change only"
  (`tests/test_ask_wording.py`, `tests/test_reach_fixed_options.py`).
- **`serve` did not show that it was listening** when its output went to a pipe or a
  file, until the first request was logged; the line is flushed, and it names the
  address bound (with `--port 0`, the port the system picked; an IPv6 host in brackets)
  (`tests/test_support_branches.py`, `tests/test_serve_startup.py`).
- **A body in another encoding than UTF-8 was read.** A UTF-16, UTF-32 or byte-order-marked
  body was decoded as such; JSON between systems is UTF-8 with no byte order mark (RFC
  8259 Section 8.1), so such a body is now refused (`tests/test_state_robustness.py`).
- **A failed key fetch told the signer about this SS's network.** Under open registration a
  `401` named the addresses the SS resolved, or the names it could not; the signer now
  gets a fixed detail and the operator's log the reason
  (`tests/test_support_branches.py`).
- **The snapshot could be written through a planted link.** Its temporary file had a fixed
  name; it is now created anew (O_EXCL) under a random one, and removed if the write fails
  (`tests/test_state_robustness.py`, `tests/test_bounded_work.py`).
- **`serve` gave no warning without an operator token.** A connect waiting on the
  confirmation page could then never be confirmed; `serve` now warns at start when a
  connect can wait on that page (under open registration, or for a trusted PS without
  `auto_connect`) (`tests/test_support_branches.py`).
- **A relay's act in a call chain was judged outside its mission.** The SS took an
  act's mission only from the request's `mission_s256`. An intermediary in a call chain
  sends no mission of its own (Protocol L842): its upstream token carries it, and its
  resource token copies it unchanged (L755). A PS that read Supervision L201 ("when it
  names one") literally and left the member out had the relay's act judged outside the
  mission, so a split exfiltration through a relay was allowed. When the request names
  no mission, the SS now takes the one the forwarded resource token or upstream token
  carries, and records the decision in it. A request whose tokens name another mission,
  or two, is refused with `invalid_request` ("mission_s256 is not the mission the
  forwarded tokens carry"). An upstream token that is not a JWT is not read: the PS
  checks it (`tests/test_delegation_chain.py`).
- **Some IPv6 addresses passed egress by the IPv4 address they carry.** Key discovery
  judged 6to4 (RFC 3056) and local-use NAT64 (`64:ff9b:1::/48`, RFC 8215) addresses as
  global on Python 3.11, so one carrying `127.0.0.1` or `169.254.169.254` passed the
  egress check there, and deprecated site-local `fec0::/10` (RFC 3879) passed on every
  version. Each such address is now judged by the IPv4 address it carries, on every
  version, and `fec0::/10` is refused (`tests/test_hardening_signatures_egress.py`).
- **A key whose `key_ops` leaves out "verify" verified signatures.** It is now refused
  (RFC 7517 Section 4.3) (`tests/test_hardening_signatures_egress.py`).
- **A 500 told the caller the exception's class.** It now carries no detail; the
  operator's log has the traceback (`tests/test_service_semantics.py`).
- Tests: `tests/test_token_lifetime_sequences.py`, including the reverse-order mission
  end to end (it fails on 0.1.0) and a differential test of the search against a
  brute-force enumeration of effect logs; `tests/test_composition_reach_scope.py` (9 of
  its 10 tests fail on 0.1.0); and the reverse-order mission with every PS request
  signed by aauth-go v0.2.0 (`tests/test_interop_aauth_go.py`, which fails on 0.1.0).
  Most fixes above name their tests, in their own entry or in this one, and each that
  does has at least one that fails on the code before it (its other tests are controls).

### Changed

- An answer's reach is offered as acts "by this agent" for the mission as well as from
  now on, since a reach is kept per agent (`tests/test_person_facing_text.py`).
- What the person reads is in the person's terms. A class is shown as the policy's name
  for it, in a code span ("`read_sensitive`, then `send_external`"), and a class budget
  by its class, then its amount ("the `payment` budget of 500000"); a prohibited
  composition is "a combination the policy forbids". Where only this act is in doubt,
  through any of its classes, an ask says the other acts are certain and gives this
  act's doubts alone, once for all such combinations. Otherwise it names, a sentence
  each, the kinds of uncertain evidence it holds for this act and for the earlier acts
  that could take one of the combination's other steps (never one of the step this act
  takes; for an act outside missions, the agent's own mission only where acts of a
  second mission, or of another agent of its provider, could take a step too; an audit
  record with no details as assumed, not as the agent's word; a class kept only with the
  agent's details set aside as that), never as the cause of what a certain act
  completes; an earlier act whose class could take a step is named though the order of
  the acts, or a certain act of its class, may leave it none. A composition the record
  does not settle is told in short sentences; budgets and metered resources without
  protocol terms, with what is offered, what is left or counted and what acts not
  reported yet may take, and "may" where an amount or a class is not known (or where
  only acts not surely of the class pass the limit); a person-token ask first says what
  the agent asks and, where the resource serves on identity, says once that it may serve
  a request on such a token, as a proposal's ask about the person tokens its approval
  would issue does; that ask speaks of "that token", or names each token it holds back,
  never of "this act". Each label names what the answer is kept by and where it applies:
  the class and target, this agent, the reason it was asked (for a resource or tool the
  mission leaves out, every mission that leaves it out; for a high-impact act, wherever
  the supervisor would ask for that reason), and the scope; a `deny` given with a reach
  applies there too, never to an act the SS would allow. Only the wording changed
  (`tests/test_ask_wording.py`, `tests/test_ask_doubts.py`,
  `tests/test_budget_texts.py`, `tests/test_policy.py`,
  `tests/test_identity_decisions.py`, `tests/test_approval_person_tokens.py`).
- `keygen`, `check-policy`, `explain` and `serve` describe each of their options in
  `--help` (`tests/test_server_cli.py`). The examples `aauth-ss --help` shows are one
  line each, so they run in PowerShell too.
- The development extra pins `http-message-signatures` at 2.0.1: `regent-httpsig` 0.7.1
  imports `http_sfv` from it, and 2.1.0 (2026-10-19) no longer exports it, so a fresh
  install could not run the regent interop tests.
- `pyproject.toml` states its license as an SPDX expression (`Apache-2.0`, with
  `license-files`), and building needs setuptools 77 or later. CI pins its actions by
  commit and does not keep the checkout's credentials.
- What 0.1.0 listed as "deferred decisions" are deferred responses: a `202` with a
  pending URL, for a connect awaiting confirmation or a clarification. They are
  unchanged. The SS never defers its own decision: `decide` runs within the request
  (Supervision L286), as README "Limitations" says.
- A server setting, `transit_allowance` (seconds, 2 by default): how long the fastest of
  a PS's requests may take to reach the SS, which reads the PS's clocks from them (README
  "Limitations"). `signature_window`, `transit_allowance` and `clarification_timeout`
  are at most a day (86,400 s); a larger value is a configuration error, as one past the
  float range would have failed every request that reads it (`tests/test_config_files.py`).
- The state snapshot holds forwarded token claims and mission text, so on POSIX it is now
  created owner-only (`0o600`), like the key `keygen` writes, through a temporary file
  created anew, so no earlier file's wider mode can carry over. Windows ignores the mode
  bits: keep the state and key files in a private directory there
  (`tests/test_state_robustness.py`).
- The snapshot is version 2 (history entries carry `token_exp`, `n`, `agent`,
  `amount_known` and `scope`, decision records `plain`, reach rows `answer`, missions
  `updates`). A version 1
  snapshot is read and migrated (a token's unknown `exp` as never expiring, an amount
  booked as 0 as unseen); 0.1.x sets a version 2 snapshot aside, so the upgrade is one
  way.
- `aauth-ss serve` says so when it set an unreadable state file aside at start.
- The conformance matrix also covers the core sections Supervision -00 incorporates by
  reference for the SS's answers (clarification, deferred responses, interaction,
  errors, identifiers, metadata), the core sections the SS meets as the verifier of
  every PS request (signature algorithms, keying material, covered components,
  parameters, verification, scheme rejection, freshness, JWKS discovery and caching,
  rows `VER-*`), and the Budgets sections this SS implements. A row this SS does not
  meet is marked `gap` with where it is documented (`tests/test_core_by_reference.py`,
  `tests/test_verifier_rows.py`). Rows whose tests passed on a non-conforming SS have
  tests that do not (`tests/test_conformance_rows.py`), the isolation of one PS from
  another is tested (`tests/test_cross_ps_isolation.py`), and rows that bind another
  role are `n/a`.
- A pluggable policy's `decide` runs while the PS waits, under the store lock; the
  README says so, and the model advisor in `examples/layered_policy.py` is bounded by a
  `timeout` (5 seconds by default) past which the person decides.
- A revocation is acknowledged and no longer kept: nothing the SS decides reads it, and
  the list only grew. A snapshot that holds one still loads.
- The snapshot keeps more members: a mission update put to the person (`update`), the
  plain gates an ask named (`gates`), when the person's answer arrived (`resolved_at`),
  whether the composition asked about was completed on certain evidence (`certain`), and
  where the history stood when the decision was recorded and its answer arrived
  (`recorded_n`, `resolved_n`) on a decision record; the further classes an act has
  (`blind`): where the agent's data raised its class, and where its class was assumed
  for data a rule did not have or, for a person token, the resource's other classes
  (`assumed`), each with whether it is certain there, the amount its rule reads and
  whether it was assumed only in the reading that does not take the agent's data as
  true (`set_aside`); whether its place is known (`unplaced`), whether its
  report came long after it (`wide`), the answer it cannot precede (`after_n`) and the
  PS's stamp on its report (`iat`) on a history entry; the gate an answer is about
  (`gate`) and whether the composition the person answered was completed on certain
  evidence (`certain`) on a reach row; whether a pending URL has given its terminal
  answer (`gone`) on a pending record and, on a pending connect, whether the person has
  opened its page (`arrived`), the `id` that opened it (`once`) and how many wrong
  operator tokens were posted with its code (`failures`); and, at the top level, how far
  ahead each PS's clocks run (`leads`, by PS: a value that is not a finite number sets
  the snapshot aside). All default to empty, so a snapshot written without them loads.
- CI also runs the gate on Python 3.14, as a preview that cannot fail the run; 3.14
  joins the supported versions once the gate passes on Linux, macOS and Windows.
  CPython 3.14 parses deeper JSON before its decoder gives up, so the
  test of a body nested past that limit now tries a depth past it on every version
  (`tests/test_state_robustness.py`).
- The conformance matrix marks its 17 rows of behaviour the draft states without a BCP 14
  keyword `prose`, not `MUST`. Seven of them now cite the line that states the
  behaviour rather than its heading or a blank line (`tests/test_release_metadata.py`).
- The `SupervisionPolicy` interface has a fourth method, `serves_on_identity(resource)`;
  a policy that does not model identity-served access returns False
  (`examples/layered_policy.py` delegates it to its floor).
- The SS `issuer` must be a server identifier (lowercase https host, no port or path).
- `iat` is any JSON number of at most 2**53 - 1 either way, where 0.1.x took only an
  integer (see Fixed). The SS reads it as the whole second it falls in wherever it
  orders, places or keeps an act: a request stamped `1790600000.9` is decided as one
  stamped `1790600000`. Three readings use the number as sent, each the cautious one. A
  retry must repeat it: under the same `sdi`, an `iat` that differs even below the
  second is a different request, refused as one (L198, L316); the same whole number
  written another way (`1790600000.0` for `1790600000`) is the same request. An `exp`
  before the stamp, even within its second, marks a token expired when issued. And a
  token the PS issues at approval ends an hour from the stamp, rounded up. NaN and the
  infinities (no JSON numbers, but Python's reader takes them) and numbers past that
  range are refused, with "member 'iat' must be a finite JSON number of at most 2**53 -
  1 either way", and the same for `exp` (`tests/test_iat_seconds.py`,
  `tests/test_conformance.py`). In 0.1.x an `iat` or `exp` that was not an integer was
  refused as "the wrong JSON type", and one past that range was taken (see Fixed).
- The Go interop now runs against the tagged `github.com/aauth-dev/aauth-go v0.2.0`
  (the repository was renamed from `auth-go`; the previous pin was a pre-release commit
  of the same draft -11 line). The signature wire format is unchanged between the two,
  and the interop tests pass unmodified. The interop command moved to
  `interop/aauth-go/` and its test to `tests/test_interop_aauth_go.py`.
- `docs/interop.md` lists the public person server implementations with a link to the
  source of each entry. None, aauth-go v0.2.0 included, has a Supervision client, so the
  end-to-end PS remains the simulated one.

## [0.1.0] - 2026-10-08: implements AAuth Supervision -00

Initial public release.

### Added

- The SS side of Supervision -00: metadata and JWKS, connect, the mission endpoint,
  the decision endpoint for `person_token`, `auth_token` and `permission`, events,
  deferred decisions and clarification (with an enforced `timeout`), signed decisions,
  idempotence, replay and recovery, and the error table.
- RFC 9421 request verification and response signing under the AAuth profile, with
  `jwks_uri` key discovery under egress admission (HTTPS only, no private destinations,
  DNS pinning, no redirects).
- The APC policy: declarative action classes, provenance on every classification,
  composition closure across resources, per-mission budgets, intent checks, and the
  reach of the person's answers. It sits behind the `SupervisionPolicy` interface, so it
  can be replaced without touching the protocol layer.
- R3 forwarding (the change [AAuth #256](https://github.com/dickhardt/AAuth/issues/256) proposes) of a per-call proposal or the R3
  document a resource token references, checked against `r3_s256`, off by default.
- Composition across a delegation chain: history is per mission, so an exfiltration
  split between a parent agent, a sub-agent (`subagent_token`) and a call chain
  (`upstream_token`) still composes.
- AAuth Budgets: per-mission ceilings at metered resources (`resource_budgets`), held
  against the `budget` offer and the signed `budget_consumed` record in the forwarded
  resource token, with every unreported allocation counted as fully consumed. Adversarial
  scenario T10 shows it deciding correctly under Supervision -00 as written.
- `aauth-ss demo`: a narrated mission run against the real server, in-process, with real
  signatures and no network (`--extension` forwards the R3 proposal; `--trace`).
- `examples/layered_policy.py`: the APC policy as a deterministic floor with an advisor
  (standing preferences, or any language model) that may refuse any act the floor would
  ask about but settle only the low-stakes ones.
- The `aauth-ss` command: `keygen`, `check-policy`, `explain` and `serve`.
- A conformance matrix generated from the pinned drafts (83 tested, 23 n/a, 0 open) and
  an adversarial suite of ten attack scenarios under four configurations.
- The offline merge gate (`tools/check.py`), run by CI on Linux, macOS and Windows with
  Python 3.11 to 3.13: ruff, mypy, 100% line and branch coverage, Hypothesis
  property and model-based lifecycle tests, and staleness checks for the generated docs.
- Mutation testing of `policy.py`, `httpsig.py` and `service.py`, with every surviving
  mutant re-verified against the full suite (`docs/mutation-testing.md`).
- Signature interop with two independent AAuth implementations in both directions:
  regent-httpsig (Python) and auth-go (Go, draft -11), plus a full mission against the
  server with every PS request signed by auth-go (`tests/test_interop_regent_httpsig.py`,
  `tests/test_interop_auth_go.py`, `interop/auth-go/`).

[Unreleased]: https://github.com/xmuruaga/aauth-supervision-server/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/xmuruaga/aauth-supervision-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/xmuruaga/aauth-supervision-server/releases/tag/v0.1.0
