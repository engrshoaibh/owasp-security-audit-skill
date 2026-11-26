# 60-second demo: OWASP Juice Shop

A recording plan for the README demo. It shows the skill finding a real SQL injection in
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) (a deliberately vulnerable training app) and proving it
against a **local** instance. Tested against Juice Shop `v20.4.0`.

> Only run the exploit step against your own local Juice Shop. Never point it at a host you are not authorized to test.

## Setup (off camera, about 2 minutes)

```bash
./examples/demo/juice-shop-demo.sh setup    # clones Juice Shop v20.4.0 source and starts it on 127.0.0.1:3000 (Docker)
```

No Docker? Download `juice-shop-20.4.0_node22_linux_x64.tgz` (or your OS/Node build) from the
[Juice Shop releases](https://github.com/juice-shop/juice-shop/releases/tag/v20.4.0), unpack it, run `npm start`,
then run `setup` anyway to clone the source and write the payload file (the container step will simply fail).

## Option A: Claude Code (best for the README)

Window: terminal at 120x32, large font, dark theme. Start in the Juice Shop source folder with the skill installed
(`/tmp/juice-demo/juice-shop`).

| Time | On screen | What to do |
|:---|:---|:---|
| 0-5s | Juice Shop home page in a browser at `localhost:3000` | Caption: "OWASP Juice Shop, a deliberately vulnerable app" |
| 5-10s | Claude Code prompt | Type: `Quick security check of routes/login.ts and routes/search.ts` |
| 10-35s | Skill runs `loophole_scanner.py --quick`, reads the flagged lines | Speed up 2-4x in editing if it runs long |
| 35-45s | Verdict: SQL injection (A05:2025, CWE-89) at `routes/login.ts:34` and `routes/search.ts:23` | Pause on the register for 3 seconds |
| 45-55s | Second terminal: `cat payload.json` then the `curl` login from the script | Shows `"umail":"admin@juice-sh.op"`: logged in as admin with no password |
| 55-60s | Caption | "Found by heuristics, verified by the agent, fixed with a parameterized query." + repo URL |

## Option B: terminal only (fully scripted, no agent)

```bash
PAUSE=1.5 ./examples/demo/juice-shop-demo.sh run
```

Runs in about 40 seconds: scanner output, the vulnerable line, the payload and the admin login. Record it with
[asciinema](https://asciinema.org/) and convert to a GIF with [agg](https://github.com/asciinema/agg):

```bash
asciinema rec demo.cast -c "PAUSE=1.5 ./examples/demo/juice-shop-demo.sh run"
agg --font-size 20 demo.cast demo.gif
```

## Publishing it in the README

- **MP4 (recommended, under 10 MB):** edit `README.md` on github.com, drag the file into the editor at the
  `DEMO-VIDEO` marker, and commit. GitHub uploads it and inserts a `https://github.com/user-attachments/...` link
  that renders as an inline player.
- **GIF:** commit it as `docs/demo.gif` and replace the marker with `![60-second demo](docs/demo.gif)`.

Finish with `./examples/demo/juice-shop-demo.sh clean`.
