let csrfToken=null, currentUser=null, devices=[], buildSubmissionEnabled=false;
const $=s=>document.querySelector(s);
const notice=(message,kind="")=>{$("#notice").textContent=message;$("#notice").className="status "+kind;};
async function api(path,options={}){
 const headers={"Content-Type":"application/json",...(options.headers||{})};
 if(csrfToken && !["GET","HEAD"].includes((options.method||"GET").toUpperCase())) headers["x-csrf-token"]=csrfToken;
 const response=await fetch(path,{...options,headers,credentials:"same-origin"});
 const data=await response.json().catch(()=>({error:"invalid_server_response"}));
 if(!response.ok) throw new Error(data.error||("HTTP "+response.status));
 return data;
}
function showWorkspace(user){
 currentUser=user;$("#auth").classList.add("hidden");$("#workspace").classList.remove("hidden");
 $("#identity").textContent=user.email+" · "+user.role;$("#logout").classList.remove("hidden");
 $("#adminPanel").classList.toggle("hidden",user.role!=="admin");
 if(user.role==="admin")loadAdminDevices().catch(err=>notice(err.message,"bad"));
}
function formData(form){return Object.fromEntries(new FormData(form).entries());}
async function loadDevices(){
 const data=await api("/api/devices");devices=data.devices;
 $("#device").innerHTML='<option value="">Choose a device</option>'+devices.map(d=>'<option value="'+d.id+'">'+esc(d.manufacturer)+" "+esc(d.model)+" ("+esc(d.codename)+")</option>").join("");
 updateBases();
}
function updateBases(){
 const d=devices.find(x=>x.id===$("#device").value);
 const bases=d?.rom_bases||[];
 $("#romBase").innerHTML=bases.length?bases.map(b=>'<option value="'+b.base+'">'+b.base+' · '+esc(b.branchName)+'</option>').join(""):'<option value="">No verified ROM base</option>';
}
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function loadAdminDevices(){
 const host=$("#adminDeviceInventory");if(!host||currentUser?.role!=="admin")return;
 const data=await api("/api/admin/devices");
 const cards=await Promise.all(data.devices.map(async d=>{
  const sourceData=await api("/api/admin/devices/"+d.id+"/sources");
  const sources=sourceData.sources.map(s=>'<div class="muted">'+esc(s.source_kind)+(s.rom_base?' · '+esc(s.rom_base):'')+' · '+esc(s.repository_url)+' · '+esc(s.branch_name)+' · <strong>'+esc(s.verification_status)+'</strong>'+(s.verified_commit_sha?' · '+esc(s.verified_commit_sha.slice(0,12)):'')+(s.verification_error?'<div class="status bad">'+esc(s.verification_error)+'</div>':'')+'<div class="actions"><button class="secondary" data-verify-source="'+d.id+'" data-source-id="'+s.id+'">Re-verify</button></div></div>').join("");
  return '<article class="card"><h3>'+esc(d.manufacturer)+' '+esc(d.model)+' ('+esc(d.codename)+')</h3><div class="tag">'+(d.enabled?'Enabled':'Disabled')+'</div><div>'+esc((d.rom_bases||[]).map(b=>b.base+': '+b.branchName).join(' · '))+'</div>'+sources+'<div class="actions">'+(!d.enabled?'<button data-activate-device="'+d.id+'">Activate if verified</button>':'<button class="secondary" data-disable-device="'+d.id+'">Disable</button>')+'</div></article>';
 }));
 host.innerHTML=cards.join("")||'<p class="muted">No device profiles registered.</p>';
}

async function loadConfigs(){
 const data=await api("/api/configurations");
 $("#configs").innerHTML=data.configurations.length?data.configurations.map(c=>'<article class="card"><h3>'+esc(c.name)+'</h3><div><span class="tag">'+esc(c.rom_base)+'</span><span class="tag">'+esc(c.status)+'</span><span class="tag">'+esc(c.root_method)+'</span></div><p>'+esc(c.manufacturer)+" "+esc(c.model)+" · "+esc(c.codename)+'</p><div class="actions"><button class="secondary" data-validate="'+c.id+'">Validate</button>'+(c.status==="validated"&&buildSubmissionEnabled?'<button data-queue="'+c.id+'">Queue build</button>':'')+'</div><pre class="muted" id="report-'+c.id+'"></pre></article>').join(""):"No saved configurations yet.";
}
async function loadBuildStatus(){
 const data=await api("/api/builds/status");
 buildSubmissionEnabled=data.submissionEnabled;
 $("#buildAvailability").textContent=buildSubmissionEnabled?"Build submission is enabled. Jobs are dispatched to registered workers.":"Build execution is disabled by the server operator. Configurations can still be saved and validated.";
}
async function loadBuildJobs(){
 const data=await api("/api/build-jobs");
 $("#buildJobs").innerHTML=data.jobs.length?data.jobs.map(job=>'<article class="card"><div class="actions"><strong>'+esc(job.configuration_name||job.id)+'</strong><span class="tag">'+esc(job.status)+'</span></div><p>'+esc(job.device_codename||"Device")+' · '+esc(job.rom_base||"ROM")+' · Job '+esc(job.id)+'</p><p>Attempts: '+esc(job.attempts)+' / '+esc(job.max_attempts)+' · Created: '+esc(new Date(job.created_at).toLocaleString())+'</p>'+(job.error_message?'<p class="status bad">'+esc(job.error_code)+': '+esc(job.error_message)+'</p>':'')+(job.artifact_sha256?'<p class="muted">Verified artifact SHA-256: '+esc(job.artifact_sha256)+' · '+esc(job.artifact_size_bytes)+' bytes</p><button class="secondary" data-download-job="'+job.id+'">Download verified ROM</button>':'')+'<p class="muted">Input snapshot SHA-256: '+esc(job.snapshot_sha256)+'</p>'+(['pending','leased'].includes(job.status)?'<button class="secondary" data-cancel-job="'+job.id+'">Cancel job</button>':'')+'</article>').join(""):"No build jobs yet.";
}
async function enter(data){
 csrfToken=data.csrfToken;showWorkspace(data.user);await loadDevices();await loadBuildStatus();await loadConfigs();await loadBuildJobs();notice("Signed in. Choose a supported device and save a configuration.","good");
}
$("#loginForm").addEventListener("submit",async e=>{e.preventDefault();try{await enter(await api("/api/auth/login",{method:"POST",body:JSON.stringify(formData(e.currentTarget))}));}catch(err){notice(err.message,"bad");}});
$("#registerForm").addEventListener("submit",async e=>{e.preventDefault();try{await enter(await api("/api/auth/register",{method:"POST",body:JSON.stringify(formData(e.currentTarget))}));}catch(err){notice(err.message,"bad");}});
$("#logout").addEventListener("click",async()=>{try{await api("/api/auth/logout",{method:"POST",body:"{}"});}catch{}csrfToken=null;currentUser=null;$("#workspace").classList.add("hidden");$("#auth").classList.remove("hidden");$("#logout").classList.add("hidden");$("#identity").textContent="Not signed in";notice("Signed out.");});
$("#device").addEventListener("change",updateBases);
$("#configForm").addEventListener("submit",async e=>{
 e.preventDefault();const f=e.currentTarget,d=formData(f);
 const payload={name:d.name,deviceId:d.deviceId,romBase:d.romBase,rootMethod:d.rootMethod,manifestRevision:d.manifestRevision||null,options:{includeGapps:f.includeGapps.checked,includeMicroG:f.includeMicroG.checked,debloatPackages:d.debloatPackages.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),featureFlags:{}}};
 try{await api("/api/configurations",{method:"POST",body:JSON.stringify(payload)});f.reset();await loadConfigs();notice("Configuration saved as a draft.","good");}catch(err){notice(err.message,"bad");}
});
$("#configs").addEventListener("click",async e=>{
 const target=e.target;
 if(!(target instanceof HTMLElement))return;
 const queueId=target.dataset.queue;
 if(queueId){try{const result=await api("/api/configurations/"+queueId+"/queue",{method:"POST",body:"{}"});notice("Build job "+result.job.id+" queued.","good");await loadConfigs();await loadBuildJobs();}catch(err){notice(err.message,"bad");}return;}
 const id=target.dataset.validate;if(!id)return;
 const out=$("#report-"+id);out.textContent="Validating…";
 try{const data=await api("/api/configurations/"+id+"/validate",{method:"POST",body:"{}"});out.textContent=JSON.stringify(data.report,null,2);await loadConfigs();notice(data.report.valid?"Configuration validated.":"Validation found issues; review the report.","good");}
 catch(err){out.textContent=err.message;notice(err.message,"bad");}
});

$("#refreshJobs").addEventListener("click",async()=>{try{await loadBuildStatus();await loadBuildJobs();await loadConfigs();notice("Build job list refreshed.","good");}catch(err){notice(err.message,"bad");}});
$("#buildJobs").addEventListener("click",async e=>{
 const target=e.target;if(!(target instanceof HTMLElement))return;
 const downloadId=target.dataset.downloadJob;
 if(downloadId){
  try{const result=await api("/api/build-jobs/"+downloadId+"/download",{method:"POST",body:"{}"});window.location.assign(result.url);}
  catch(err){notice(err.message,"bad");}
  return;
 }
 const id=target.dataset.cancelJob;if(!id)return;
 try{await api("/api/build-jobs/"+id+"/cancel",{method:"POST",body:"{}"});await loadBuildJobs();await loadConfigs();notice("Build job cancelled.","good");}catch(err){notice(err.message,"bad");}
});
$("#adminDeviceInventory").addEventListener("click",async e=>{
 const target=e.target;
 if(!(target instanceof HTMLElement))return;
 try{
  if(target.dataset.verifySource){
   const result=await api("/api/admin/devices/"+target.dataset.verifySource+"/sources/"+target.dataset.sourceId+"/verify",{method:"POST",body:"{}"});
   notice(result.status==="verified"?"Source verified at "+result.commitSha.slice(0,12):"Source verification failed: "+result.error,result.status==="verified"?"good":"bad");
  }else if(target.dataset.activateDevice){
   await api("/api/admin/devices/"+target.dataset.activateDevice+"/activate",{method:"POST",body:"{}"});
   notice("Device activated.","good");
  }else if(target.dataset.disableDevice){
   await api("/api/admin/devices/"+target.dataset.disableDevice,{method:"DELETE",body:"{}"});
   notice("Device disabled.","good");
  }else return;
  await loadAdminDevices();await loadDevices();
 }catch(err){notice(err.message,"bad");await loadAdminDevices().catch(()=>{});}
});

$("#deviceForm").addEventListener("submit",async e=>{
 e.preventDefault();const f=e.currentTarget,d=formData(f),romBases=[];
 if(f.lineage.checked)romBases.push({base:"lineage",manifestPath:"default.xml",branchName:d.lineageBranch,enabled:true});
 if(f.crdroid.checked)romBases.push({base:"crdroid",manifestPath:"snippets/crdroid.xml",branchName:d.crdroidBranch,enabled:true});
 if(!romBases.length){notice("Select at least one ROM base.","bad");return;}
 const payload={codename:d.codename,manufacturer:d.manufacturer,model:d.model,chipset:d.chipset||null,architecture:d.architecture,enabled:false,notes:null,romBases};
 try{
  const created=await api("/api/admin/devices",{method:"POST",body:JSON.stringify(payload)});
  const pendingSources=[];
  for(const base of romBases){
   const treeBranch=base.base==="lineage"?d.lineageDeviceBranch:d.crdroidDeviceBranch;
   const source=await api("/api/admin/devices/"+created.id+"/sources",{method:"POST",body:JSON.stringify({
    sourceKind:"device",romBase:base.base,repositoryUrl:d.deviceRepositoryUrl,branchName:treeBranch,sourcePath:d.deviceRepositoryPath||""
   })});
   pendingSources.push({base:base.base,sourceId:source.sourceId});
  }
  const verifiedCommits=[];
  for(const pending of pendingSources){
   const verification=await api("/api/admin/devices/"+created.id+"/sources/"+pending.sourceId+"/verify",{method:"POST",body:"{}"});
   if(verification.status!=="verified")throw new Error(pending.base+" device-tree verification failed: "+verification.error+"; profile remains disabled.");
   verifiedCommits.push(verification.commitSha.slice(0,12));
  }
  await api("/api/admin/devices/"+created.id+"/activate",{method:"POST",body:"{}"});
  f.reset();await loadDevices();await loadAdminDevices();notice("Device tree verified for every selected ROM base at "+verifiedCommits.join(", ")+" and device activated.","good");
 }catch(err){await loadDevices().catch(()=>{});await loadAdminDevices().catch(()=>{});notice(err.message,"bad");}
});
(async()=>{try{const data=await api("/api/auth/me");await enter(data);}catch{}})();
