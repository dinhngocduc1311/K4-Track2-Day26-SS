# RULES.md — the submission contract
### Vi phạm là loại bài, không phải trừ điểm. *A violation is disqualification, not a deduction.*


> ### `CONTRACTS.md` không có trong kit — và đó là cố ý
>
> Rất nhiều file ở đây trích dẫn `CONTRACTS.md §x.y`. Đó là bản đặc tả của
> giảng viên: nó chứa **đúng cái mà trọng tài chấm bạn dựa vào**. Phát nó ra là
> phát luôn đáp án.
>
> Bạn **không thiếu gì cả**. Mọi thứ cần để làm bài đều có trong kit, ở dạng
> chạy được: shape của `Decision`/`ToolCall` nằm trong `agent/gateway.py` và
> `kit/mcp/types.py`; schema của claim và cú pháp bằng chứng nằm trong
> `RULES.md` + `eval/prosecute.py`; đủ 17 lớp lỗi và trọng số nằm trong
> `README.md` §5 và trong rubric chạy được ở `eval/prosecute.py`.
>
> Khi thấy `CONTRACTS.md §x.y`, hãy đọc nó như một số hiệu điều khoản — không
> phải một file bạn cần đi tìm.
>
> *`CONTRACTS.md` is the instructor's spec and is deliberately not shipped: it is
> the oracle the referee scores against. You are not missing anything — every
> shape, schema, class and weight you need is in the kit in executable form.
> Read a `CONTRACTS.md §x.y` citation as a clause number, not as a file to hunt
> for.*

---

## 1. What you own, and what you must not touch

**You own, entirely:** `agent/` · `deck/` · `eval/`

**You must not modify:** `kit/` · `bots/` · `fixtures/`

A hash gate runs at submission. If any file under `kit/` differs from the shipped version, the
bundle is rejected — **read it all you like; that is encouraged, and `bots/operator/` in particular
is the most instructive thing in the kit.** Editing it is what fails.

---

## 2. Imports

**Standard library only.** No third-party packages, in any of your three directories.

**Denied outright, and checked mechanically:**

```
socket · ssl · http.client · urllib.request · urllib3 · requests · httpx · asyncio.open_connection
subprocess · os.system · os.exec* · os.spawn* · multiprocessing · ctypes · cffi
importlib.util.spec_from_file_location   (loading code from outside your directories)
```

Your code runs inside a **kernel sandbox** (`sandbox-exec`), so most of these will fail at the OS
level anyway. The list exists so that you fail at *submission* time, where you can fix it, rather
than mid-duel, where you cannot.

---

## 3. `Gateway.decide` — the hard constraints

```python
def decide(self, cmd: Command) -> Decision:
```

| Constraint | Value | If you break it |
|---|---|---|
| **Synchronous** | no `async`, no threads, no `sleep` | `integrity` event, command denied |
| **Pure decision** | **no I/O of any kind** | sandbox denial, recorded |
| **Deadline** | **250 ms wall** | 2 cr penalty, command denied |
| **Return type** | a valid `Decision` | 2 cr penalty, command denied |
| **Raises** | anything | 2 cr penalty, command denied, `enforcement_failure` becomes available to the prosecutor |

**There is no `execute` method on your context, and that is deliberate.** You return a decision; the
arena carries it out. It is the reason your trace cannot be forged — and equally, the reason nobody
can accuse you of a call you did not authorise.

`deny` costs **0 credits**. Refusing is free. That is what makes abstention a real strategy rather
than a luxury.

---

## 4. `eval/prosecute.py`

```python
def prosecute(trace: list[dict], answer: dict, card: dict) -> dict:
```

- **Synchronous, no I/O, no network.** 5 s deadline.
- **At most 4 claims per exchange, at most 1 per family.** Prosecution is a case, not a dragnet.
- Every claim needs `cls`, `evidence`, `expected`, `observed`, `argument` (≤ 400 chars).
- **A false claim costs `0.8 × the weight of the class you filed`.** The penalty scales with the
  class deliberately: under a flat penalty, blind filing on a weight-10 class pays off at only 28.6%
  accuracy, so shotgunning the heavy classes would be rational. Scaling makes the break-even
  **44.4% for every class**, so there is no weight to shop for.

You receive the opponent's **L1 events only**, with their own telemetry removed. You never receive
their source.

---

## 5. `deck/` — legality

14 cards: **10 attacks + 4 blanks.** You play 10 in a locked order, no repeats.

- ≥3 MCP-layer · ≥3 A2A-layer · ≥2 gateway-layer · ≥6 distinct classes of the nine
- **every `replica_flip` card must name a `path_id` in the measured drift set** — roughly a third of
  days do not drift at all, and a card aimed at one of them finds nothing
- lethality band: it must fall to `rookie` and be held by `adversary`

`make validate` checks the mechanical card rules offline. The local mutation
engine can replay attacks, but the instructor's truth and scored arena are needed
to measure the lethality band; validation reports it as a warning. **Invalid cards never enter the tournament** — they are rejected at
lock, not at play, so validate early.

---

## 6. Things that score zero, by name

Each of these has a test in the arena, and each was a real degeneracy someone tried:

| Degeneracy | What happens |
|---|---|
| A `deny` with no matching effect — refusing everything | scores nothing; blanks punish it at 8 |
| A memorised constant answer | zero on a fresh mutation seed |
| Routing on the body instead of the header | caught by `header_spoof` |
| A double write with no idempotency key | trips exactly-once → `write_violation` |
| A claim naming several classes at once | `rejected` |
| Reading another team's directory | kernel-denied **and** recorded as a scored `integrity` event |

**Probing the sandbox teaches you nothing and is recorded.** It is not a clever line of attack; it
is a line in the report.

---

## 7. Collaboration

Within your team: anything. Across teams: **nothing** — no shared `agent/`, no shared `deck/`, no
shared prosecutor heuristics.

Reading the AI20K course material, the lecture slides, the RESEARCH companions and every public lab
repo is **actively encouraged** — that is the world you are playing in, and knowing it is the point.

You may use AI assistants to write your code. You may not hand one your opponent's trace during the
tournament: prosecution is scored live and is your team's own work.

---

## 8. Submission

```bash
make submit TEAM=<your-team-name>
```

Produces `submissions/<team>.bundle` containing `agent/`, `deck/`, `eval/`, a manifest, and the
hashes of the `kit/` Python files recorded by the local packer. Keep all `kit/`
files unchanged; the submission hash gate may check more than the local manifest.

**Deadline is the session start.** `agent/` and `deck/` lock then; the session itself is sparring,
prosecution, and the tournament.
