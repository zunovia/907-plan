// ===================================================
// vive-qa: chkAllFixed / chkAllBank 機能検証テスト
// ===================================================
let pass = 0, fail = 0;

function assert(name, cond, detail) {
  if (cond) {
    console.log('  PASS:', name);
    pass++;
  } else {
    console.error('  FAIL:', name, detail || '');
    fail++;
  }
}

// ----- モックデータ -----
let fixedRows = [
  { id: 'J001', en: true,  amt: 200000, cat: '給与' },
  { id: 'J002', en: true,  amt: 0,      cat: '給与' },
  { id: 'J010', en: false, amt: 0,      cat: '減価償却' },
];
let bankRows = [
  { id: 1, inc: true,  st: 'ok',    amt: 10000, drCd:'1113',  crCd:'4211' },
  { id: 2, inc: false, st: 'skip',  amt: 5000,  drCd:'1113',  crCd:'4211' },
  { id: 3, inc: true,  st: 'check', amt: 3000,  drCd:'CHECK', crCd:'4211' },
];

// ----- 関数実装（index.js 1324-1325行を再現） -----
let renderFixedCalled = false;
let renderBankCalled  = false;
let updateTopCount    = 0;

function renderFixed() { renderFixedCalled = true; }
function renderBank()  { renderBankCalled  = true; }
function updateTop()   { updateTopCount++; }

function chkAllFixed(val) {
  fixedRows.forEach(function(r){ r.en = val; });
  renderFixed();
  updateTop();
}
function chkAllBank(val) {
  bankRows.forEach(function(r){ r.inc = val; });
  renderBank();
  updateTop();
}

// ===================================================
// テスト B-1: chkAllFixed(true)
// ===================================================
console.log('\n[B-1] chkAllFixed(true) -- 全件 en=true');
renderFixedCalled = false; updateTopCount = 0;
chkAllFixed(true);
assert('J001.en === true', fixedRows[0].en === true);
assert('J002.en === true', fixedRows[1].en === true);
assert('J010.en === true', fixedRows[2].en === true);
assert('renderFixed() 呼ばれた', renderFixedCalled === true);
assert('updateTop() 呼ばれた', updateTopCount >= 1);

// ===================================================
// テスト B-2: chkAllFixed(false)
// ===================================================
console.log('\n[B-2] chkAllFixed(false) -- 全件 en=false');
renderFixedCalled = false; updateTopCount = 0;
chkAllFixed(false);
assert('J001.en === false', fixedRows[0].en === false);
assert('J002.en === false', fixedRows[1].en === false);
assert('J010.en === false', fixedRows[2].en === false);
assert('renderFixed() 呼ばれた', renderFixedCalled === true);
assert('updateTop() 呼ばれた', updateTopCount >= 1);

// ===================================================
// テスト B-3: chkAllBank(true)
// ===================================================
console.log('\n[B-3] chkAllBank(true) -- 全件 inc=true');
renderBankCalled = false; updateTopCount = 0;
chkAllBank(true);
assert('row1.inc === true', bankRows[0].inc === true);
assert('row2(skip).inc === true にセットされる', bankRows[1].inc === true);
assert('row3.inc === true', bankRows[2].inc === true);
assert('renderBank() 呼ばれた', renderBankCalled === true);
assert('updateTop() 呼ばれた', updateTopCount >= 1);

// ===================================================
// テスト B-4: chkAllBank(false)
// ===================================================
console.log('\n[B-4] chkAllBank(false) -- 全件 inc=false');
renderBankCalled = false; updateTopCount = 0;
chkAllBank(false);
assert('row1.inc === false', bankRows[0].inc === false);
assert('row2.inc === false', bankRows[1].inc === false);
assert('row3.inc === false', bankRows[2].inc === false);
assert('renderBank() 呼ばれた', renderBankCalled === true);
assert('updateTop() 呼ばれた', updateTopCount >= 1);

// ===================================================
// テスト C-1: buildTKC相当フィルタ -- r.en && r.amt>0
// ===================================================
console.log('\n[C-1] buildTKC フィルタ: r.en && r.amt>0');
chkAllFixed(true);
let fn = fixedRows.filter(function(r){ return r.en && r.amt > 0; });
assert('全選択後、amt>0の行のみ出力 (1件)', fn.length === 1, 'got: ' + fn.length);
assert('J001が含まれる', fn[0].id === 'J001');

chkAllFixed(false);
fn = fixedRows.filter(function(r){ return r.en && r.amt > 0; });
assert('全解除後、出力0件', fn.length === 0, 'got: ' + fn.length);

// ===================================================
// テスト C-2: bankRows フィルタ -- r.inc && r.st!=='skip' && !CHECK
// ===================================================
console.log('\n[C-2] bankRows フィルタ: r.inc && r.st!==skip && !CHECK');
chkAllBank(true);
let bn = bankRows.filter(function(r){ return r.inc && r.st !== 'skip' && r.drCd !== 'CHECK' && r.crCd !== 'CHECK'; });
assert('全選択後、skip/CHECK除いた件数 (1件)', bn.length === 1, 'got: ' + bn.length);
assert('row1のみ出力', bn[0].id === 1);

// skip行: inc=true がセットされても出力フィルタで除外されることを確認
let skipInc = bankRows.filter(function(r){ return r.inc && r.st === 'skip'; });
assert('skip行に inc=true がセットされている', skipInc.length === 1);
let skipFiltered = skipInc.filter(function(r){ return r.st !== 'skip'; });
assert('skip行はフィルタ後に出力されない', skipFiltered.length === 0);

chkAllBank(false);
bn = bankRows.filter(function(r){ return r.inc && r.st !== 'skip' && r.drCd !== 'CHECK' && r.crCd !== 'CHECK'; });
assert('全解除後、bank出力0件', bn.length === 0, 'got: ' + bn.length);

// ===================================================
// テスト C-4: updateTop カウント・合計検証
// ===================================================
console.log('\n[C-4] updateTop() カウント・合計');
chkAllFixed(true);
let fa = fixedRows.filter(function(r){ return r.en; }).reduce(function(s,r){ return s+r.amt; }, 0);
assert('全選択後の fa = 200000', fa === 200000, 'got: ' + fa);
let cnt_en = fixedRows.filter(function(r){ return r.en; }).length;
assert('全選択後の件数 = 3', cnt_en === 3, 'got: ' + cnt_en);

chkAllFixed(false);
fa = fixedRows.filter(function(r){ return r.en; }).reduce(function(s,r){ return s+r.amt; }, 0);
assert('全解除後の fa = 0', fa === 0, 'got: ' + fa);
cnt_en = fixedRows.filter(function(r){ return r.en; }).length;
assert('全解除後の件数 = 0', cnt_en === 0, 'got: ' + cnt_en);

// ===================================================
// テスト D-1: fixedRows 空のとき
// ===================================================
console.log('\n[D-1] fixedRows 空のとき');
let savedFixed = fixedRows;
fixedRows = [];
renderFixedCalled = false;
try {
  chkAllFixed(true);
  assert('空でも例外なし (true)', true);
  assert('renderFixed()呼ばれた', renderFixedCalled === true);
} catch(e) {
  assert('空でも例外なし (true)', false, e.message);
}
renderFixedCalled = false;
try {
  chkAllFixed(false);
  assert('空でも例外なし (false)', true);
  assert('renderFixed()呼ばれた(false)', renderFixedCalled === true);
} catch(e) {
  assert('空でも例外なし (false)', false, e.message);
}
fixedRows = savedFixed;

// ===================================================
// テスト D-2: bankRows 空のとき
// ===================================================
console.log('\n[D-2] bankRows 空のとき');
let savedBank = bankRows;
bankRows = [];
renderBankCalled = false;
try {
  chkAllBank(true);
  assert('空でも例外なし (true)', true);
  assert('renderBank()呼ばれた', renderBankCalled === true);
} catch(e) {
  assert('空でも例外なし (true)', false, e.message);
}
renderBankCalled = false;
try {
  chkAllBank(false);
  assert('空でも例外なし (false)', true);
  assert('renderBank()呼ばれた(false)', renderBankCalled === true);
} catch(e) {
  assert('空でも例外なし (false)', false, e.message);
}
bankRows = savedBank;

// ===================================================
// テスト D-3: 一部選択 -> 全選択 -> 全解除 -> 個別選択
// ===================================================
console.log('\n[D-3] 往復操作');
fixedRows[0].en = true; fixedRows[1].en = true; fixedRows[2].en = false;
let before = fixedRows.filter(function(r){return r.en;}).length;
assert('初期: en=true 2件', before === 2, 'got: ' + before);

chkAllFixed(true);
assert('全選択後: en=true 3件', fixedRows.filter(function(r){return r.en;}).length === 3);

chkAllFixed(false);
assert('全解除後: en=false 3件', fixedRows.filter(function(r){return r.en;}).length === 0);

fixedRows[0].en = true;
assert('個別選択後: en=true 1件', fixedRows.filter(function(r){return r.en;}).length === 1);
assert('J001のみtrue', fixedRows[0].en === true);
assert('J002はfalse', fixedRows[1].en === false);
assert('J010はfalse', fixedRows[2].en === false);

// ===================================================
// 結果
// ===================================================
console.log('\n===================================');
console.log('テスト結果: PASS=' + pass + '  FAIL=' + fail);
if (fail === 0) {
  console.log('判定: PASS');
} else {
  console.log('判定: FAIL');
  process.exit(1);
}
