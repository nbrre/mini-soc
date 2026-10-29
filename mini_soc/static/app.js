// Dashboard for Mini-SOC. Bygger DOM med textContent (ikke innerHTML) så data fra logger ikke kan kjøre som kode.
const $ = (tag, attrs = {}, ...barn) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (el.className = v) : el.setAttribute(k, v);
  for (const b of barn) el.append(b instanceof Node ? b : document.createTextNode(String(b ?? "")));
  return el;
};
const kl = iso => iso.replace("T", " ").slice(0, 16);

async function lastSaker() {
  const saker = await (await fetch("/api/saker")).json();
  document.getElementById("oppsummering").textContent =
    `${saker.length} saker · ${saker.filter(s => s.alvor === "kritisk").length} kritiske`;
  const liste = document.getElementById("liste");
  liste.replaceChildren(...saker.map(s => {
    const kort = $("div", { class: "sak" },
      $("span", { class: `merke ${s.alvor}` }, s.alvor.toUpperCase()), " ",
      $("strong", {}, `#${s.id} ${s.tittel}`),
      $("div", { class: "dempet" }, `${kl(s.start)} · ${s.brukere.join(", ")} · ${s.status}`));
    kort.onclick = () => { document.querySelectorAll(".sak").forEach(e => e.classList.remove("valgt")); kort.classList.add("valgt"); visSak(s.id); };
    return kort;
  }));
}

async function visSak(id) {
  const s = await (await fetch(`/api/saker/${id}`)).json();
  const d = document.getElementById("detalj");
  const knapp = $("button", {}, s.rapport ? "Etterforsk på nytt med KI" : "Etterforsk med KI-agent");
  knapp.onclick = async () => {
    knapp.disabled = true; knapp.textContent = "Agenten jobber …";
    const r = await fetch(`/api/saker/${id}/etterforsk`, { method: "POST" });
    if (!r.ok) alert((await r.json()).feil);
    await lastSaker(); visSak(id);
  };
  const deler = [
    $("h2", {}, `#${s.id} ${s.tittel}`),
    $("p", {}, $("span", { class: `merke ${s.alvor}` }, s.alvor.toUpperCase()), " ",
      $("span", { class: "dempet" }, `${kl(s.start)} – ${kl(s.slutt)} · brukere: ${s.brukere.join(", ") || "–"} · IP: ${s.ipadresser.join(", ") || "–"}`)),
    $("div", { class: "faser" }, "Angrepsfaser: ", ...s.faser.map(f => $("span", {}, f))),
    $("h3", {}, "Varsler"),
    $("div", { class: "tidslinje" }, ...s.varsler.map(v =>
      $("div", {}, $("span", { class: `merke ${v.alvor}` }, v.alvor), " ", $("strong", {}, kl(v.tid)), " ", v.tittel,
        $("div", { class: "dempet" }, `${v.regel} · ${v.mitre} · kilde: ${v.kilde}`)))),
    knapp,
  ];
  if (s.rapport) {
    const r = s.rapport;
    deler.push($("h3", {}, `KI-rapport (${r.sikkerhet} % sikker)`), $("p", {}, r.oppsummering),
      $("h3", {}, "Tidslinje"), $("ul", {}, ...r.tidslinje.map(t => $("li", {}, `${t.tid}: ${t.hendelse}`))),
      $("h3", {}, "Strakstiltak"), $("ol", {}, ...r.tiltak_na.map(t => $("li", {}, t))),
      $("h3", {}, "Senere"), $("ul", {}, ...(r.tiltak_senere || []).map(t => $("li", {}, t))),
      $("h3", {}, "Varsling"), $("p", {}, r.varsling),
      $("p", { class: "dempet" }, `MITRE ATT&CK: ${r.mitre.join(", ")}`));
  }
  if (s.notater?.length) deler.push($("h3", {}, "Agentens notater"), $("ul", {}, ...s.notater.map(n => $("li", {}, n.tekst))));
  d.replaceChildren(...deler);
}

lastSaker();
