import './local-audits-preview.mjs';
const results = document.createElement('pre'); results.id='interactive-test-results'; document.body.append(results);
let failures=0; const assert=(name,value)=>{results.textContent+=`${value?'PASS':'FAIL'} ${name}\n`;if(!value)failures++;};
const settle=async()=>{for(let i=0;i<12;i++)await new Promise(r=>setTimeout(r,0));};
const $=id=>document.querySelector(`#disposable-${id}`);
try {
    await settle();const dashboard=window.dashboard, workspace=dashboard.disposableWorkspace;
    dashboard.switchManagementWorkspace('disposable');await settle();
    assert('full app navigation opens interactive sessions',!$('workspace').classList.contains('hidden'));
    assert('Small 8 GiB / 2 vCPUs is default', $('memory').value==='8' && $('cpus').value==='2');
    $('size').value='medium'; $('size').dispatchEvent(new Event('change'));
    $('name').value='Long build';$('github-token').value='fixture-only-token';$('create-form').dispatchEvent(new Event('submit',{cancelable:true}));
    assert('GitHub token clears synchronously', $('github-token').value==='');await settle();
    assert('Medium VM starts with until-deleted lifetime',workspace.detail.request.memory_mb===12288&&workspace.detail.request.vcpus===4&&workspace.detail.request.lifetime==='until_deleted');
    assert('token does not appear in session request',!JSON.stringify(workspace.detail).includes('fixture-only-token'));
    workspace.terminal.term.paste('pwd\r');await settle();
    const text=()=>{const b=workspace.terminal.term.buffer.active;return Array.from({length:b.length},(_,i)=>b.getLine(i)?.translateToString()).join('\n');};
    assert('terminal receives simulated command output',text().includes('/workspace'));
    dashboard.switchManagementWorkspace('audits');dashboard.switchManagementWorkspace('disposable');await settle();assert('returning preserves terminal work',text().includes('/workspace'));
    $('name').value='Second task';await workspace.create();await settle();assert('two Medium VMs fit shared capacity',workspace.sessions.filter(s=>s.state==='running').length===2);assert('third VM disabled at CPU limit',$('create').disabled);
    $('delete-workspace').click();assert('deletion asks before discarding work',$('delete-dialog').open&&$('delete-description').textContent.includes('Nothing is exported'));$('delete-back').click();assert('keeping workspace leaves it running',workspace.detail.state==='running');
    $('delete-workspace').click();$('delete-confirm').click();await settle();assert('confirmed deletion releases capacity',workspace.sessions.filter(s=>s.state==='running').length===1&&!$('create').disabled);
    for (const session of workspace.sessions.filter(s=>s.state==='running')) await workspace.client.remove(session.id);
    await workspace.refresh(); $('size').value='small'; $('size').dispatchEvent(new Event('change'));
    for(let index=0;index<4;index++){ $('name').value=`Small task ${index+1}`; await workspace.create(); }
    assert('four Small VMs fit 32 GiB / 8 vCPU capacity',workspace.sessions.filter(s=>s.state==='running').length===4 && workspace.resourceUsage.memory_mb_used===32768 && workspace.resourceUsage.vcpus_used===8);
    assert('fifth Small VM is disabled at shared cap',$('create').disabled);
    for(const name of ['console','fleet','celld','config','access']){dashboard.switchManagementWorkspace(name);assert(`legacy ${name} view remains accessible`,document.querySelector(`[data-workspace="${name}"]`).classList.contains('active'));}
    workspace.setActive(false);
} catch(error){assert(`unexpected exception: ${error.message}`,false);}
document.body.dataset.result=failures?'fail':'pass';document.body.dataset.failures=String(failures);results.style.cssText='position:fixed;inset:16px;z-index:999;background:white;padding:24px;overflow:auto';
