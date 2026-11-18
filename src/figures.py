import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = json.load(open(os.path.join(ROOT, "results", "results.json")))
FIG = os.path.join(ROOT, "figs")
os.makedirs(FIG, exist_ok=True)
INK, INK2, MUTED, GRID, BASE, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#ffffff"
BLUE, ORANGE = "#2a78d6", "#eb6834"
SEQ = ["#f0efec", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5, "axes.edgecolor": BASE,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False})
DEF = ["B0", "B1", "B1+", "B2", "B3", "PBT"]
LABEL = {"B0": "B0 none", "B1": "B1 pattern DLP", "B1+": "B1+ normalizing DLP", "B2": "B2 redaction",
         "B3": "B3 pseudonymization", "PBT": "PBT (proposed)"}

# ---- Fig 2: attempt-level leakage by encoding (heatmap)
enc = list(R["E1_exfiltration"]["B0"]["by_encoding"])
M = [[R["E1_exfiltration"][d]["by_encoding"][e] * 100 for e in enc] for d in DEF]
fig, ax = plt.subplots(figsize=(7.0, 2.6), dpi=300)
cmap = LinearSegmentedColormap.from_list("seq", SEQ)
im = ax.imshow(M, cmap=cmap, vmin=0, vmax=100, aspect="auto")
ax.set_xticks(range(len(enc))); ax.set_xticklabels([e.replace("_", " ") for e in enc], rotation=30, ha="right")
ax.set_yticks(range(len(DEF))); ax.set_yticklabels([LABEL[d] for d in DEF])
for i in range(len(DEF)):
    for j in range(len(enc)):
        v = M[i][j]
        ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=7, color="#ffffff" if v >= 55 else INK)
for s in ax.spines.values(): s.set_visible(False)
ax.tick_params(length=0)
cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01); cb.set_label("Successful attempts (%)", color=INK2)
cb.outline.set_visible(False)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig2_leak_by_encoding.png"), facecolor=SURF); plt.close(fig)

# ---- Fig 3: worst-case leakage and utility (two panels, same % scale)
leak = [R["E1_exfiltration"][d]["worst_case_leak_rate"] * 100 for d in DEF]
util = [R["E2_utility"][d]["overall"] * 100 for d in DEF]
fig, axs = plt.subplots(1, 2, figsize=(7.0, 2.5), dpi=300, sharey=True)
for ax, vals, title in [(axs[0], leak, "(a) Worst-case leakage (%)\nlower is better"),
                        (axs[1], util, "(b) Legitimate tasks completed (%)\nhigher is better")]:
    y = range(len(DEF))
    ax.barh(list(y), vals, height=0.55, color=BLUE, edgecolor=SURF, linewidth=1)
    for yi, v in zip(y, vals):
        ax.text(v + 1.5, yi, f"{v:.0f}", va="center", fontsize=7.5, color=INK)
    ax.set_xlim(0, 112); ax.set_title(title, fontsize=8.5, color=INK, loc="left")
    ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
    ax.invert_yaxis() if ax is axs[0] else None
axs[0].set_yticks(range(len(DEF))); axs[0].set_yticklabels([LABEL[d] for d in DEF])
fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig3_leak_vs_utility.png"), facecolor=SURF); plt.close(fig)

# ---- Fig 4: balance inference vs predicate budget
keys = ["3", "5", "10", "20", "unlimited"]
widths = [R["E4_inference"][k]["median_interval_SAR"] for k in keys]
fig, ax = plt.subplots(figsize=(3.6, 2.4), dpi=300)
ax.plot(range(len(keys)), widths, color=BLUE, linewidth=2, marker="o", markersize=5,
        markeredgecolor=SURF, markeredgewidth=1.5)
for i, w in enumerate(widths):
    ax.annotate(f"{w:,.0f}" if w >= 1 else f"{w:.2f}", (i, w), textcoords="offset points", xytext=(0, 6),
                ha="center", fontsize=7, color=INK)
ax.set_yscale("log"); ax.set_xticks(range(len(keys))); ax.set_xticklabels(keys)
ax.set_xlabel("Predicate queries allowed per session"); ax.set_ylabel("Attacker's uncertainty (SAR, log)")
ax.yaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig4_inference_budget.png"), facecolor=SURF); plt.close(fig)

# ---- Fig 1: architecture
fig, ax = plt.subplots(figsize=(7.0, 3.3), dpi=300); ax.set_xlim(0, 100); ax.set_ylim(0, 47); ax.axis("off")
def box(x, y, w, h, title, sub="", fc="#f6f6f4", ec=BASE, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec=ec, lw=1))
    ax.text(x + w / 2, y + h - 1.8, title, ha="center", va="top", fontsize=7.8, color=INK, weight="bold" if bold else "normal")
    if sub:
        ax.text(x + w / 2, y + h - 5.2, sub, ha="center", va="top", fontsize=6.4, color=INK2, linespacing=1.2)
def arrow(p, q, txt="", tx=None, ty=None, ha="center"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=8, color=INK2, lw=0.9, shrinkA=0, shrinkB=0))
    if txt:
        ax.text(tx, ty, txt, ha=ha, va="center", fontsize=6.2, color=INK2, linespacing=1.15)
box(1, 29, 17, 13, "Bank data APIs", "account, card,\nidentity records")
box(1, 3, 17, 13, "User", "task, approvals,\nown display channel")
box(30, 1.5, 30, 43, "PBT gateway (trusted)", "", fc="#eef4fc", ec=BLUE, bold=True)
box(32.5, 29, 25, 10.5, "Ingress tokenizer", "value -> opaque token\n+ minimized view")
box(32.5, 16, 25, 10.5, "Vault and bindings", "AES-256-GCM at rest; slot,\ncap, uses, TTL, session")
box(32.5, 3, 25, 10.5, "Egress enforcer", "re-identifies only in\nbound typed slots")
box(71, 29, 27, 13, "LLM agent (untrusted)", "sees tok_9f3a... and\n**** 1234, 10000-50000 SAR;\nmay be hijacked")
box(71, 3, 27, 13, "Tools", "trusted: payment, transfer, gov\nexternal: e-mail, SMS, HTTP")
arrow((18.4, 35.5), (32.1, 34.3), "raw values", 23.5, 37.6)
arrow((18.4, 9.5), (32.1, 20.5), "grant for one\nrecipient", 22.6, 17.5)
arrow((57.9, 34.3), (70.6, 34.3), "tokens\n+ views", 65.6, 37.6)
arrow((76, 28.6), (57.9, 10.5), "tool call\nwith tokens", 70.2, 20.5, ha="left")
arrow((57.9, 6.5), (70.6, 6.5), "real value\nin bound\nslot only", 65.6, 2.6)
arrow((45, 28.6), (45, 26.9)); arrow((45, 15.6), (45, 13.9))
fig.savefig(os.path.join(FIG, "fig1_architecture.png"), facecolor=SURF, bbox_inches="tight"); plt.close(fig)
print("ok")
