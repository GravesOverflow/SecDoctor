const SEC_DOCTOR_SESSION = new URLSearchParams(location.hash.slice(1)).get("session") || "";
if (SEC_DOCTOR_SESSION) history.replaceState(null, "", location.pathname + location.search);
const secDoctorFetch = window.fetch.bind(window);
window.fetch = (input, init = {}) => {
  const url = typeof input === "string" ? input : input.url;
  if (new URL(url, location.href).origin === location.origin && new URL(url, location.href).pathname.startsWith("/api/")) {
    const headers = new Headers(init.headers || (typeof input !== "string" ? input.headers : undefined));
    headers.set("X-SecDoctor-Session", SEC_DOCTOR_SESSION);
    init = {...init, headers};
  }
  return secDoctorFetch(input, init);
};
const $=s=>document.querySelector(s),esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));let vulns=[],filter="ALL",currentPlan=null,lastBefore=0,lastPlanID="";
function renderV(){let a=filter==="ALL"?vulns:vulns.filter(v=>v.severity===filter);$("#vlist").innerHTML=a.length?a.map(v=>`<article class="vuln"><div><span class="badge ${esc(v.severity)}">${esc(v.severity)}</span></div><div><h3>${esc(v.id)} · ${esc(v.package)}@${esc(v.version)}</h3><p>${esc(v.summary||"Known vulnerability reported for this dependency.")}</p><div class="facts">${v.cve?`<span>${esc(v.cve)}</span>`:""}${v.cvss?`<span>CVSS ${v.cvss.toFixed(1)}</span>`:""}${v.epss?`<span>EPSS ${(v.epss*100).toFixed(2)}%</span>`:""}${v.known_exploited?`<span>⚠ CISA KEV</span>`:""}</div></div><div class="fix"><b>Recommended action</b>${v.fixed_versions?.length?`Review compatibility and upgrade to ${esc(v.fixed_versions.join(", "))}.`:"Review the advisory and upgrade to a non-affected release."}</div></article>`).join(""):`<div class="empty">✓ No ${filter==="ALL"?"known dependency vulnerabilities":filter.toLowerCase()+" vulnerabilities"} found.</div>`}
document.querySelectorAll(".filter").forEach(b=>b.onclick=()=>{document.querySelectorAll(".filter").forEach(x=>x.classList.remove("active"));b.classList.add("active");filter=b.dataset.f;renderV()});
async function runFullAudit(){let b=$("#scan");b.disabled=true;$("#progress").classList.remove("hidden");$("#welcome").classList.add("hidden");$("#dash").classList.add("hidden");try{let r=await fetch("/api/audit",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:$("#path").value.trim()||"."})}),d=await r.json();if(!r.ok)throw Error(d.error||"Audit failed");vulns=d.vulnerabilities||[];let hi=vulns.filter(v=>v.severity==="HIGH"||v.severity==="CRITICAL").length,med=vulns.filter(v=>v.severity==="MEDIUM").length;$("#vulns").textContent=vulns.length;$("#vnav").textContent=vulns.length;$("#high").textContent=hi;$("#medium").textContent=med;$("#deps").textContent=d.dependencies;$("#files").textContent=d.files;$("#elapsed").textContent=`Completed in ${d.duration_ms}ms`;const status=d.security_status||"UNKNOWN";$("#headline").textContent=status==="PROVIDER_UNAVAILABLE"?"Security provider unavailable":status==="PARTIAL_RESULTS"?"Audit completed with partial intelligence":vulns.length?"Dependency risks found":"Full audit completed";$("#subline").textContent=status==="PROVIDER_UNAVAILABLE"?"Dependency safety is UNKNOWN. SecDoctor will not report this scan as clean.":status==="PARTIAL_RESULTS"?"Some security intelligence providers failed; results are incomplete.":vulns.length?`${vulns.length} known advisories require review.`:"Verified clean against the completed dependency provider set.";$("#root").textContent=d.root;$("#finger").textContent=d.fingerprint;$("#stages").innerHTML=(d.stages||[]).map(s=>`<span class="stage ${esc(s.status)}">✓ ${esc(s.name)} · ${s.duration_ms<1?"<1":s.duration_ms}ms</span>`).join("");let lf=d.local_findings||[];$("#localCount").textContent=`${lf.length} finding${lf.length===1?"":"s"}`;$("#llist").innerHTML=lf.length?lf.map(f=>`<div class="finding"><b><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)}</b><p>${esc(f.explanation)} · ${esc(f.file||"project")}</p></div>`).join(""):`<div class="empty">✓ No local file or configuration findings.</div>`;let warnings=d.warnings||[];if(warnings.length){$("#warning").textContent="Audit completed with warnings: "+warnings.join(" · ");$("#warning").classList.remove("hidden")}else $("#warning").classList.add("hidden");$("#fixbar").classList.toggle("hidden",!(vulns.length&&d.dependencies>0));if(status==="PROVIDER_UNAVAILABLE"||status==="PARTIAL_RESULTS"){$("#fixbar").classList.add("hidden")}filter="ALL";document.querySelectorAll(".filter").forEach(x=>x.classList.toggle("active",x.dataset.f==="ALL"));renderV();$("#dash").classList.remove("hidden");$("#exportReport").disabled=false;$("#exportReport").classList.remove("muted")}catch(e){$("#welcome").classList.remove("hidden");let t=$("#toast");t.textContent=e.message;t.classList.remove("hidden");setTimeout(()=>t.classList.add("hidden"),5000)}finally{$("#progress").classList.add("hidden");b.disabled=false}}
$("#scan").onclick=runFullAudit;
$("#planFix").onclick=async()=>{
 const b=$("#planFix");b.disabled=true;b.textContent="Building safe preview…";
 try{
  const r=await fetch("/api/fix/plan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:$("#path").value.trim(),fixes:buildFixTargets()})});
  const d=await readAPI(r);
  if(!r.ok)throw Error(d.error||"Could not create fix plan");currentPlan=d;$("#applyFix").disabled=true;$("#labproof").classList.add("hidden");
  $("#changes").innerHTML=d.changes.map(c=>`<div class="change"><div><b>${esc(c.package)}</b> ${c.direct?'<span class="direct">DIRECT</span>':""}</div><code>${esc(c.from)} <span class="arrow">→</span> ${esc(c.to)}</code><small>package-lock.json</small></div>`).join("");
  $("#fixplan").classList.remove("hidden");$("#fixplan").scrollIntoView({behavior:"smooth",block:"center"});
 }catch(e){show(e.message)}finally{b.disabled=false;b.textContent="Preview fix"}
};
$("#closePlan").onclick=$("#cancelFix").onclick=()=>{$("#fixplan").classList.add("hidden");currentPlan=null};

$("#verifyLab").onclick=async()=>{
 if(!currentPlan)return;const b=$("#verifyLab");b.disabled=true;b.textContent="Running isolated verification…";
 try{
  const r=await fetch("/api/fix/lab",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plan_id:currentPlan.id,run_tests:$("#runTests").checked})});
  const d=await readAPI(r);if(!r.ok)throw Error(d.error||"Lab verification failed");
  const tests=d.tests_run?(d.tests_passed?"passed":"failed"):(d.tests_available?"not run":"not available");
  const backend=d.backend==="docker"?"Hardened Docker container":"Isolated workspace fallback";
  $("#labproof").innerHTML=`<strong>ISOLATED PROOF READY</strong><br>Backend: ${esc(backend)} · Assurance: ${esc(d.assurance)}<br>Install: ${d.install_passed?"passed":"failed"} · Tests: ${esc(tests)} · Original project untouched: ${d.working_tree_untouched?"yes":"NO"}<br>Network: ${esc(d.network_policy)}<br>Signature: ${d.signature_algorithm==="Ed25519"?"Ed25519 ✓":"unavailable"}<br><code>Proof ${esc(d.proof_sha256)}</code>`;
  $("#labproof").classList.remove("hidden");
  $("#applyFix").disabled=!(d.install_passed&&d.working_tree_untouched&&(!d.tests_run||d.tests_passed));
 }catch(e){show(e.message)}finally{b.disabled=false;b.textContent="Verify in isolated lab"}
};

$("#applyFix").onclick=async()=>{
 if(!currentPlan)return;const b=$("#applyFix");b.disabled=true;b.textContent="Applying…";lastBefore=vulns.length;
 try{
  const r=await fetch("/api/fix/apply",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plan_id:currentPlan.id,sync_runtime:$("#syncRuntime").checked,run_tests:$("#runTests").checked})});
  const d=await readAPI(r);
  if(!r.ok)throw Error(d.error||"Fix failed");
  const planID=currentPlan.id;lastPlanID=planID;$("#fixplan").classList.add("hidden");
  // Re-run the exact same audit after the lockfile change: this is the proof step.
  await runFullAudit();
  const after=vulns.length;
  const runtimeLabel=d.runtime_status==="verified"?"Installed runtime synchronized":d.runtime_status==="not_installed"?"Lockfile verified; node_modules is not installed":d.runtime_status==="failed"?"Runtime synchronization failed":"Lockfile verified; installed runtime not checked";
  const testLabel=d.tests_run?`Tests: ${d.tests_passed?"passed":"failed"}.`:"No runnable test script detected.";
  $("#verified").innerHTML=`<b>Verification complete:</b> ${lastBefore} → ${after} known advisories. <strong>${esc(runtimeLabel)}.</strong> ${esc(testLabel)} <button id="rollbackNow">Roll back</button>`;
  $("#verified").classList.remove("hidden");
  $("#rollbackNow").onclick=async()=>{const rr=await fetch("/api/fix/rollback",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plan_id:planID,sync_runtime:true})});const x=await readAPI(rr);if(rr.ok){const rt=x.runtime_status==="verified"?" Runtime restored and synchronized.":x.runtime_status==="not_previously_installed"?" Runtime was not installed before remediation.":" Lockfile restored; runtime not synchronized.";$("#verified").textContent="Rollback complete."+rt+" Re-run the audit to verify the restored state."}else{show(x.error||"Rollback failed")}};
  currentPlan=null;
 }catch(e){show(e.message)}finally{b.disabled=false;b.textContent="Apply, test & verify"}
};
function show(m){const t=$("#toast");t.textContent=m;t.classList.remove("hidden");setTimeout(()=>t.classList.add("hidden"),5000)}

function buildFixTargets(){
 const fixes={};
 for(const v of vulns){
  for(const fv of (v.fixed_versions||[])){
   if(!fixes[v.package]||semverCmp(fv,fixes[v.package])>0)fixes[v.package]=fv;
  }
 }
 return fixes;
}
function semverCmp(a,b){
 const pa=String(a).replace(/^v/,"").split(/[.-]/).slice(0,3).map(x=>parseInt(x,10)||0);
 const pb=String(b).replace(/^v/,"").split(/[.-]/).slice(0,3).map(x=>parseInt(x,10)||0);
 for(let i=0;i<3;i++){if(pa[i]!==pb[i])return pa[i]-pb[i]}return 0;
}

async function readAPI(response){
 const text=await response.text();
 try{return JSON.parse(text)}
 catch(e){
  const clean=text.replace(/\s+/g," ").trim();
  return {error:`SecDoctor API returned invalid JSON (${response.status}): ${clean.slice(0,500)||"empty response"}`};
 }
}


$("#exportReport").onclick=async()=>{
 const b=$("#exportReport");b.disabled=true;const old=b.textContent;b.textContent="Generating report…";
 try{
  const r=await fetch("/api/report/export",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:$("#path").value.trim()||".",plan_id:lastPlanID})});
  const d=await readAPI(r);if(!r.ok)throw Error(d.error||"Report export failed");
  downloadText(d.markdown_filename,d.markdown,"text/markdown;charset=utf-8");
  downloadText(d.json_filename,d.json,"application/json;charset=utf-8");
  $("#reportReady").innerHTML=`<b>Security report exported.</b> ${esc(d.markdown_filename)} + ${esc(d.json_filename)}`;
  $("#reportReady").classList.remove("hidden");
 }catch(e){show(e.message)}finally{b.disabled=false;b.textContent=old}
};
function downloadText(name,content,type){
 const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const a=document.createElement("a");
 a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
