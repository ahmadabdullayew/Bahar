"""Offline Chromium browser regression tests with fully mocked API responses.
Checks frontend-only behavior and responsive presentation, not live infrastructure.
Usage: python scripts/verify_frontend.py
"""
from pathlib import Path
from shutil import which
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
WEB=ROOT/'web'
SNAPSHOTS=ROOT/'artifacts'
SNAPSHOTS.mkdir(exist_ok=True)
HTML=(WEB/'index.html').read_text().replace('<script type="module" src="/app.js"></script>','')
CSS=(WEB/'styles.css').read_text()
JS=(WEB/'app.js').read_text()
MOCK=r'''
window.__calls={suppliers:0};
window.fetch=async function(input,options={}){
 const path=String(input).replace(/^.*\/api\//,'');
 const json=(value,status=200)=>Promise.resolve(new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}}));
 if(path==='health')return json({status:'ok',production_persistence:true,bahar_ai_core:{mode:'deterministic_lexical_candidate_engine'}});
 if(path==='dashboard')return json({counts:{suppliers:1,materials:1,supplier_lots:1,receipts:1,formulations:1,artworks:1,batches:1,inspections:1,cross_contact_assessments:1},recent_audit_events:[]});
 if(path.startsWith('demo/'))return json({assessment_contract:{id:'demo'},product_id:'demo'});
 if(path.startsWith('records/suppliers')){window.__calls.suppliers++;if(window.__calls.suppliers===5)return json({error:'refresh_test_failure'},503);return json({records:[{supplier_id:'11111111-aaaa-4aaa-aaaa-000000000001',supplier_code:'SUP-001',legal_name:'Supplier A',status:'active'}],has_more:false,limit:40,offset:0});}
 if(path.startsWith('records/'))return json({records:[],has_more:false,limit:40,offset:0});
 if(path==='ai/audit'){const payload=JSON.parse(options.body);if(payload.product_id==='fail-me')return json({error:'simulated_service_failure'},503);return json({assessment_id:'scoped-001',execution_status:'COMPLETED',technical_readiness:'BLOCKED',coverage:{ratio:1},context:{product_id:payload.product_id,recipe_version:'1',label_version:'1'},knowledge_status:'EDITORIAL_SEED_NOT_DOMAIN_VALIDATED',checks:{candidate_extraction:'PASS',label_comparison:'FAIL'},findings:[{code:'POTENTIAL_MISSING_DISCLOSURE',allergen:'sesame',message:'Candidate origin lacks a label mention',legal_violation_confirmed:false}],candidates:[{text:'sesame'}]});}
 if(path.startsWith('ai/lookup'))return json({lookup_status:'EXACT_ALIAS_CANDIDATE',concept_id:'ing-sesame'});
 if(path==='suppliers')return json({supplier_id:'11111111-aaaa-4aaa-aaaa-000000000002'},201);
 if(path==='documents')return json({state:'accepted',artifact_id:'a1',artifact_version:1,extraction:{state:'failed',message:'Simulated OCR failure'}},201);
 if(path==='assess')return json({execution_status:'COMPLETED',technical_readiness:'NEEDS_REVIEW',checks:{legal_applicability:'INDETERMINATE'},findings:[]});
 return json({error:'not_found'},404);
};
'''
def make_page(browser,width,height,errors):
 page=browser.new_page(viewport={'width':width,'height':height})
 page.on('pageerror',lambda exc:errors.append(str(exc)))
 page.set_content(HTML,wait_until='domcontentloaded')
 page.add_style_tag(content=CSS)
 page.evaluate(MOCK)
 page.add_script_tag(content=JS)
 return page

errors=[]
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,**({'executable_path':which('chromium') or which('google-chrome')} if which('chromium') or which('google-chrome') else {}),args=['--no-sandbox'])
 page=make_page(browser,1400,900,errors)
 page.locator('#dashboard-stats .stat-card').first.wait_for()
 assert page.locator('#dashboard-stats .stat-card').count()==9,'dashboard metric truncation'
 assert page.locator('.nav-item[aria-current=page]').count()==1,'no semantic active navigation'
 page.locator('.nav-item[data-view="ai"]').click()
 assert page.url.endswith('#/ai'),page.url
 page.locator('#ai-form button.primary').click()
 page.locator('#ai-summary .finding').first.wait_for()
 assert 'blocked' in page.locator('#ai-summary').inner_text().lower()
 assert 'Potential Missing Disclosure' in page.locator('#ai-summary').inner_text()
 assert 'Legal verdict' in page.locator('#ai-summary').inner_text()
 assert 'Submitted-text comparison' in page.locator('#ai-summary').inner_text()
 assert 'COMPLETED' in page.locator('#ai-state').inner_text()
 page.wait_for_timeout(350)
 page.screenshot(path=str(SNAPSHOTS/'audit-results-desktop.png'),full_page=False)
 page.locator('#ai-form input[name="product_id"]').fill('fail-me')
 page.locator('#ai-form button.primary').click()
 page.get_by_text('Latest attempt #2: processing failed').wait_for()
 assert 'HISTORICAL RESULT' in page.locator('#ai-result').text_content()
 assert 'FAILED' in page.locator('#ai-state').inner_text()
 page.locator('.nav-item[data-view="supply"]').click()
 assert page.locator('form.json-form .structured-fields').count()>=10,'no structured data UI'
 page.locator('#supply-records .record-group').first.wait_for()
 assert page.locator('#supply-records .record-group').count()==6
 page.locator('form[data-endpoint="/api/suppliers"] input[name="supplier_code"]').fill('SUP1')
 page.locator('form[data-endpoint="/api/suppliers"] input[name="legal_name"]').fill('Supplier one')
 page.locator('form[data-endpoint="/api/suppliers"] button.primary').click()
 page.get_by_text('Committed · Supplier Id',exact=False).wait_for()
 page.locator('.nav-item[data-view="labels"]').click()
 assert page.locator('#document-form .field-help').count()==1
 page.locator('#document-form input[name="document_identity"]').fill('sample-source-001')
 page.locator('#document-form input[name="file"]').set_input_files({'name':'example.pdf','mimeType':'application/pdf','buffer':b'%PDF-1.4\nmock content'})
 page.locator('#document-form button.primary').click()
 page.locator('#document-outcome.partial').wait_for()
 assert 'Extraction failed' in page.locator('#document-outcome').inner_text()
 assert 'partial' in page.locator('#document-outcome').get_attribute('class'),'failed extraction mislabeled as accepted-complete'
 page.wait_for_timeout(350)
 page.screenshot(path=str(SNAPSHOTS/'desktop-verified.png'),full_page=True)
 mobile=make_page(browser,390,844,errors)
 assert mobile.locator('#primary-navigation').is_hidden(),'mobile nav expected collapsed'
 mobile.locator('#mobile-nav-toggle').click()
 assert mobile.locator('#primary-navigation').is_visible(),'mobile nav toggle failed'
 mobile.locator('.nav-item[data-view="ai"]').click()
 mobile.locator('#primary-navigation').wait_for(state='hidden',timeout=5000)
 mobile.wait_for_timeout(350)
 mobile.screenshot(path=str(SNAPSHOTS/'mobile-verified.png'),full_page=True)
 for width in [320,390,768,1024,1440]:
  mobile.set_viewport_size({'width':width,'height':780})
  scroll=mobile.evaluate('document.documentElement.scrollWidth - window.innerWidth')
  assert scroll<=1,f'page overflow at width={width}: {scroll}'
 assert not errors, errors
 print('PASS: 9 dashboard metrics; semantic hash navigation; findings and statuses')
 print('PASS: failed latest assessment cannot be confused with historical results')
 print('PASS: structured JSON business forms; committed-write feedback and record rendering')
 print('PASS: responsive navigation and page reflow at 320, 390, 768, 1024, 1440px')
 print('PASS: no uncaught JavaScript exceptions in offline browser regression tests')
 browser.close()
