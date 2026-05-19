// ocr-public Worker
// Serves HTML + transparent AI API proxy (no data storage)

const HTML_CONTENT = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SmartBooks | AI経理アシスタント</title>
<meta name="description" content="SmartBooks - レシート・領収書PDFをAI OCRで自動読取→仕分け→会計ソフト用に出力。APIキーはブラウザ内のみ保存、サーバー送信なし。">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Noto+Sans+JP:wght@400;500;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.mini.min.js"></script>
<style>
/* ===== DESIGN SYSTEM — SmartBooks Green & Natural ===== */
:root{
  --ink:#1a2e1a;--ink2:#3d5a3d;--ink3:#7a937a;
  --bg:#f5f8f5;--bg2:#eaf0ea;
  --sf:#fff;--sf-glass:rgba(255,255,255,.82);
  --bd:rgba(180,210,180,.4);--bd2:rgba(160,195,160,.5);
  --gn:#15803d;--gnbg:#f0fdf4;--gn2:#22c55e;--gn3:#166534;
  --bl:#15803d;--blbg:#f0fdf4;--bl2:#16a34a;
  --am:#b45309;--ambg:#fffbeb;
  --rd:#dc2626;--rdbg:#fef2f2;
  --cy:#0d9488;--cybg:#f0fdfa;
  --r:12px;--r-lg:16px;
  --shadow-sm:0 1px 3px rgba(20,60,20,.05),0 1px 2px rgba(20,60,20,.03);
  --shadow-md:0 4px 16px rgba(20,60,20,.07),0 2px 4px rgba(20,60,20,.03);
  --shadow-lg:0 12px 40px rgba(20,60,20,.10),0 4px 8px rgba(20,60,20,.05);
  --shadow-glow:0 0 30px rgba(21,128,61,.12);
  --gradient-hero:linear-gradient(135deg,#14532d 0%,#166534 30%,#15803d 60%,#22c55e 100%);
  --gradient-btn:linear-gradient(135deg,#15803d,#16a34a);
  --gradient-btn-g:linear-gradient(135deg,#15803d,#22c55e);
  --gradient-btn-b:linear-gradient(135deg,#0d9488,#14b8a6);
  --ease-bounce:cubic-bezier(.34,1.56,.64,1);
  --ease-smooth:cubic-bezier(.4,0,.2,1);
}

/* ===== ANIMATIONS ===== */
@keyframes sp{to{transform:rotate(360deg)}}
@keyframes fadeInUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
@keyframes borderRotate{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes pulse-ring{0%{transform:scale(.95);opacity:1}100%{transform:scale(1.15);opacity:0}}
@keyframes gradient-shift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}

/* ===== RESET & BASE ===== */
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Noto Sans JP','Inter',sans-serif;background:var(--bg);color:var(--ink);font-size:13px;line-height:1.7;
  background-image:radial-gradient(ellipse at 20% 0%,rgba(34,197,94,.04) 0%,transparent 60%),
                    radial-gradient(ellipse at 80% 100%,rgba(13,148,136,.03) 0%,transparent 60%)}

/* ===== TOOLBAR ===== */
.tb{background:linear-gradient(135deg,rgba(20,83,45,.97),rgba(22,101,52,.95));backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);
  height:60px;display:flex;align-items:center;padding:0 24px;gap:12px;
  position:sticky;top:0;z-index:300;border-bottom:1px solid rgba(255,255,255,.1);
  box-shadow:0 2px 20px rgba(20,83,45,.25)}
.tb-logo{font-size:17px;font-weight:700;color:#fff;text-decoration:none;letter-spacing:-.03em;
  font-family:'Inter','Noto Sans JP',sans-serif;display:flex;align-items:center;gap:8px}
.tb-logo::before{content:'';display:inline-block;width:28px;height:28px;border-radius:8px;
  background:linear-gradient(135deg,rgba(255,255,255,.25),rgba(255,255,255,.08));
  border:1px solid rgba(255,255,255,.2);flex-shrink:0;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M6 2a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6H6zm7 1.5L18.5 9H13V3.5zM8 13h8v1.5H8V13zm0 3h8v1.5H8V16zm0 3h5v1.5H8V19z'/%3E%3C/svg%3E");
  background-size:18px;background-repeat:no-repeat;background-position:center}
.tb-badge{font-size:9px;background:rgba(255,255,255,.15);padding:3px 9px;border-radius:20px;color:rgba(255,255,255,.85);
  border:1px solid rgba(255,255,255,.2);font-weight:600;letter-spacing:.02em}
.tb-sp{flex:1}
.tb-stat{font-size:11px;color:rgba(255,255,255,.6);font-family:'DM Mono',monospace;margin:0 8px;white-space:nowrap}
.tb-btn{background:rgba(255,255,255,.1);color:rgba(255,255,255,.85);border:1px solid rgba(255,255,255,.18);
  padding:7px 18px;border-radius:8px;font-size:12px;cursor:pointer;font-family:inherit;font-weight:500;
  transition:all .25s var(--ease-smooth);backdrop-filter:blur(8px)}
.tb-btn:hover{background:rgba(255,255,255,.2);color:#fff;border-color:rgba(255,255,255,.3);transform:translateY(-1px)}
.tb-dl{background:rgba(255,255,255,.92);color:#15803d;border:none;padding:7px 20px;border-radius:8px;font-size:12px;font-weight:700;
  cursor:pointer;font-family:inherit;transition:all .25s var(--ease-smooth);box-shadow:0 2px 8px rgba(0,0,0,.1)}
.tb-dl:hover{box-shadow:0 4px 16px rgba(0,0,0,.15);transform:translateY(-1px);background:#fff}
.tb-dl:disabled{opacity:.35;cursor:not-allowed;box-shadow:none;transform:none;filter:none}

/* ===== LAYOUT ===== */
.wrap{max-width:1100px;margin:0 auto;padding:28px 24px 80px}

/* ===== CARDS ===== */
.card{background:var(--sf);
  border:1px solid var(--bd);border-radius:var(--r-lg);overflow:hidden;margin-bottom:18px;
  box-shadow:var(--shadow-sm);transition:box-shadow .3s var(--ease-smooth),transform .3s var(--ease-smooth),border-color .3s;
  animation:fadeInUp .5s var(--ease-smooth) both}
.card:hover{box-shadow:var(--shadow-md);border-color:rgba(21,128,61,.2)}
.cardh{padding:14px 18px;display:flex;align-items:center;gap:8px;
  border-bottom:1px solid var(--bd);background:rgba(240,253,244,.5);flex-wrap:wrap}
.cardt{font-size:13px;font-weight:700;flex:1;color:var(--ink);letter-spacing:-.01em}

/* ===== BUTTONS ===== */
.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 16px;border:none;border-radius:8px;
  font-size:12px;font-family:inherit;font-weight:600;cursor:pointer;
  transition:all .25s var(--ease-smooth);white-space:nowrap;position:relative;overflow:hidden}
.btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.15),transparent);opacity:0;transition:opacity .25s}
.btn:hover::after{opacity:1}
.btn-g{background:var(--gradient-btn-g);color:#fff;box-shadow:0 2px 8px rgba(21,128,61,.2)}
.btn-g:hover{box-shadow:0 4px 16px rgba(21,128,61,.3);transform:translateY(-1px)}
.btn-o{background:var(--sf);border:1px solid var(--bd2);color:var(--ink);box-shadow:var(--shadow-sm)}
.btn-o:hover{background:var(--gnbg);border-color:var(--gn);color:var(--gn);transform:translateY(-1px);box-shadow:var(--shadow-md)}
.btn-r{background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;box-shadow:0 2px 8px rgba(220,38,38,.2)}
.btn-r:hover{box-shadow:0 4px 16px rgba(220,38,38,.3);transform:translateY(-1px)}
.btn-b{background:var(--gradient-btn-b);color:#fff;box-shadow:0 2px 8px rgba(13,148,136,.2)}
.btn-b:hover{box-shadow:0 4px 16px rgba(13,148,136,.3);transform:translateY(-1px)}
.btn-sm{padding:5px 12px;font-size:11px;border-radius:6px}

/* ===== TABLE ===== */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 10px;background:rgba(240,253,244,.6);border-bottom:1px solid var(--bd);
  font-size:10px;font-weight:700;color:var(--ink3);white-space:nowrap;text-transform:uppercase;letter-spacing:.04em}
td{padding:7px 10px;border-bottom:1px solid rgba(220,240,220,.5);vertical-align:middle;transition:background .15s}
tr:last-child td{border:none}
tr:hover td{background:rgba(21,128,61,.03)}
.ar{text-align:right;font-family:'DM Mono',monospace;font-weight:500}

/* ===== FORM ELEMENTS ===== */
input,select,textarea{font-family:'Noto Sans JP',sans-serif;font-size:11px;padding:4px 8px;
  border:1px solid var(--bd2);border-radius:6px;background:var(--sf);color:var(--ink);outline:none;
  transition:all .2s var(--ease-smooth)}
input:focus,select:focus,textarea:focus{border-color:var(--gn);box-shadow:0 0 0 3px rgba(21,128,61,.08)}

/* ===== CHIPS ===== */
.chip{font-size:9px;font-weight:700;padding:3px 8px;border-radius:20px;letter-spacing:.02em}
.cg{background:var(--gnbg);color:var(--gn);border:1px solid rgba(21,128,61,.15)}
.cb{background:rgba(240,253,244,.8);color:var(--gn);border:1px solid rgba(21,128,61,.15)}
.ca{background:var(--ambg);color:var(--am);border:1px solid rgba(180,83,9,.15)}

/* ===== DROP ZONE ===== */
.drop{position:relative;border:2px dashed rgba(21,128,61,.28);border-radius:var(--r-lg);padding:48px 30px;
  text-align:center;cursor:pointer;background:rgba(255,255,255,.7);
  margin-bottom:18px;transition:all .35s var(--ease-smooth);overflow:hidden}
.drop::before{content:'';position:absolute;inset:-2px;border-radius:var(--r-lg);
  background:linear-gradient(135deg,#15803d,#22c55e,#0d9488,#15803d);background-size:300% 300%;
  animation:gradient-shift 4s ease infinite;opacity:0;transition:opacity .35s;z-index:-1;padding:2px;
  -webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude}
.drop:hover{border-color:transparent;background:rgba(240,253,244,.8);transform:translateY(-2px);box-shadow:var(--shadow-lg)}
.drop:hover::before{opacity:1}
.drop.dg{border-color:transparent;background:rgba(240,253,244,.9);transform:scale(1.01);box-shadow:var(--shadow-glow)}
.drop.dg::before{opacity:1}
.drop.processing{border-color:var(--gn);background:var(--gnbg);pointer-events:none}
.drop.processing::before{opacity:0}

/* ===== FILE PILLS ===== */
.pills{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.pill{display:flex;align-items:center;gap:5px;background:var(--sf);
  border:1px solid var(--bd);border-radius:20px;padding:4px 12px;font-size:11px;
  box-shadow:var(--shadow-sm);animation:fadeInUp .3s var(--ease-smooth) both}
.pill .x{cursor:pointer;color:#ccc;font-size:14px;line-height:1;transition:color .15s}.pill .x:hover{color:var(--rd)}

/* ===== LOADING ===== */
.ld{display:none;background:rgba(240,253,244,.9);backdrop-filter:blur(12px);border:1px solid rgba(21,128,61,.15);
  border-radius:var(--r);padding:14px 18px;align-items:center;gap:12px;margin-bottom:14px;
  box-shadow:var(--shadow-sm);animation:fadeInUp .4s var(--ease-smooth) both}
.ld.on{display:flex}
.spin{width:18px;height:18px;border:2.5px solid rgba(21,128,61,.15);border-top-color:var(--gn);
  border-radius:50%;animation:sp .7s linear infinite;flex-shrink:0}
.ld-text{font-size:12px;font-weight:600;color:var(--gn)}
.ld-sub{font-size:10px;color:var(--gn);opacity:.6;margin-left:auto;font-family:'DM Mono',monospace}

/* ===== NOTIFICATIONS ===== */
.notif{position:fixed;bottom:20px;right:20px;background:rgba(20,83,45,.94);backdrop-filter:blur(16px);
  color:#fff;padding:12px 20px;border-radius:var(--r);font-size:12px;font-weight:500;
  box-shadow:0 8px 32px rgba(0,0,0,.2);z-index:999;transform:translateY(80px);opacity:0;
  transition:all .4s var(--ease-bounce);border:1px solid rgba(255,255,255,.1)}
.notif.on{transform:translateY(0);opacity:1}
.notif.err{background:rgba(220,38,38,.92);border-color:rgba(255,255,255,.15)}

/* ===== HERO ===== */
.concept{background:var(--gradient-hero);background-size:200% 200%;animation:gradient-shift 8s ease infinite;
  border-radius:20px;padding:44px 36px;margin-bottom:24px;color:#fff;position:relative;overflow:hidden;
  box-shadow:0 8px 32px rgba(20,83,45,.25),inset 0 1px 0 rgba(255,255,255,.1)}
.concept::before{content:'';position:absolute;top:-50%;right:-20%;width:60%;height:200%;
  background:radial-gradient(ellipse,rgba(255,255,255,.06) 0%,transparent 60%);pointer-events:none}
.concept::after{content:'';position:absolute;bottom:-30%;left:-10%;width:50%;height:150%;
  background:radial-gradient(ellipse,rgba(34,197,94,.12) 0%,transparent 60%);pointer-events:none}

/* ===== SUMMARY CARDS ===== */
.sum-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;margin-bottom:18px}
.sum-card{background:var(--sf);border:1px solid var(--bd);
  border-radius:var(--r);padding:18px 20px;box-shadow:var(--shadow-sm);
  transition:all .25s var(--ease-smooth);animation:fadeInUp .4s var(--ease-smooth) both;
  border-left:3px solid var(--gn)}
.sum-card:hover{box-shadow:var(--shadow-md);transform:translateY(-2px)}
.sum-lbl{font-size:10px;font-weight:700;color:var(--ink3);text-transform:uppercase;letter-spacing:.06em}
.sum-val{font-size:20px;font-weight:700;font-family:'DM Mono',monospace;margin-top:4px;
  color:var(--gn3)}

/* ===== TABLE INPUTS ===== */
td input[type="text"],td input[type="number"]{width:100%;border:none;background:transparent;padding:3px 2px;font-size:12px;border-radius:4px;transition:all .15s}
td input[type="text"]:focus,td input[type="number"]:focus{background:rgba(21,128,61,.04);padding:3px 6px;box-shadow:0 0 0 2px rgba(21,128,61,.08)}
td select{border:none;background:transparent;font-size:11px;padding:2px 0;cursor:pointer;max-width:130px;transition:background .15s}
td select:focus{background:rgba(21,128,61,.04);border-radius:4px}
td .del-row{cursor:pointer;color:#d4d4d8;font-size:15px;transition:all .2s;display:inline-flex;align-items:center;justify-content:center;
  width:24px;height:24px;border-radius:6px}.del-row:hover{color:var(--rd);background:rgba(220,38,38,.06)}

/* ===== EMPTY STATE ===== */
.empty{text-align:center;padding:60px 20px;color:var(--ink3);animation:fadeInUp .5s var(--ease-smooth) both}

/* ===== SECURITY BANNER ===== */
.sec-banner{background:rgba(240,253,244,.8);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border:1px solid rgba(21,128,61,.12);border-radius:var(--r);padding:18px 22px;margin-bottom:22px;
  display:flex;align-items:flex-start;gap:14px;box-shadow:var(--shadow-sm);
  animation:fadeInUp .4s var(--ease-smooth) both;position:relative;overflow:hidden}
.sec-banner::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,#15803d,#22c55e,#0d9488)}
.sec-icon{font-size:22px;flex-shrink:0;line-height:1.3;filter:drop-shadow(0 2px 4px rgba(21,128,61,.15))}
.sec-text{font-size:12px;color:#14532d;line-height:1.8}
.sec-text strong{font-weight:700}
.sec-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(21,128,61,.08);
  border:1px solid rgba(21,128,61,.15);border-radius:20px;padding:2px 10px;
  font-size:10px;font-weight:700;color:var(--gn);margin-left:6px;vertical-align:middle}
.sec-link{color:var(--gn);text-decoration:none;cursor:pointer;font-size:11px;font-weight:600;
  border-bottom:1px dashed rgba(21,128,61,.35);transition:all .2s}
.sec-link:hover{color:#166534;border-bottom-color:#166534}

/* ===== MODAL ===== */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(10,30,10,.45);backdrop-filter:blur(6px);
  z-index:500;justify-content:center;align-items:flex-start;padding:40px 16px;overflow-y:auto}
.modal-bg.on{display:flex}
.modal{background:var(--sf);border-radius:var(--r-lg);width:100%;max-width:680px;
  max-height:calc(100vh - 80px);overflow-y:auto;
  box-shadow:0 24px 80px rgba(0,0,0,.2),0 0 0 1px rgba(255,255,255,.1);
  animation:fadeInUp .35s var(--ease-bounce) both;border:1px solid var(--bd)}
.modal-h{padding:16px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;
  position:sticky;top:0;background:rgba(255,255,255,.97);backdrop-filter:blur(12px);z-index:1}
.modal-h h3{font-size:15px;flex:1;font-weight:700;letter-spacing:-.01em}
.modal-close{background:none;border:none;font-size:20px;cursor:pointer;color:var(--ink3);padding:4px 8px;
  border-radius:6px;transition:all .2s}
.modal-close:hover{color:var(--ink);background:rgba(0,0,0,.05)}
.modal-body{padding:20px 24px}
.modal-body h4{font-size:12px;font-weight:700;margin:16px 0 8px;color:var(--ink2);
  display:flex;align-items:center;gap:8px}
.modal-body h4:first-child{margin-top:0}
.modal-body h4::before{content:'';display:inline-block;width:3px;height:14px;border-radius:2px;
  background:var(--gradient-btn);flex-shrink:0}

/* ===== FORM ROWS ===== */
.form-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.form-row label{font-size:12px;font-weight:600;min-width:100px;flex-shrink:0;color:var(--ink2)}
.form-row input,.form-row select{flex:1;padding:8px 12px;font-size:12px;border-radius:8px;
  border:1px solid var(--bd2);transition:all .2s var(--ease-smooth)}
.form-row input:focus,.form-row select:focus{border-color:var(--gn);box-shadow:0 0 0 3px rgba(21,128,61,.08)}
.form-row input[type="password"]{font-family:'DM Mono',monospace}

/* ===== ACCOUNT LIST ===== */
.acct-list{max-height:300px;overflow-y:auto;border:1px solid var(--bd);border-radius:8px;background:rgba(255,255,255,.5)}
.acct-item{display:flex;align-items:center;gap:8px;padding:6px 10px;border-bottom:1px solid rgba(220,240,220,.5);font-size:12px;
  transition:background .15s}
.acct-item:last-child{border:none}
.acct-item:hover{background:rgba(21,128,61,.02)}
.acct-item input{flex:1;border:none;background:transparent;font-size:12px;padding:3px 6px;border-radius:4px;transition:background .15s}
.acct-item input:focus{background:rgba(21,128,61,.04)}
.acct-item .acct-del{cursor:pointer;color:#d4d4d8;font-size:15px;padding:0 4px;transition:color .15s;
  display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:6px}
.acct-item .acct-del:hover{color:var(--rd);background:rgba(220,38,38,.06)}

/* ===== HOW-IT-WORKS ===== */
.how-section{background:var(--sf);border:1px solid var(--bd);
  border-radius:var(--r-lg);padding:32px;margin-bottom:20px;box-shadow:var(--shadow-sm);
  animation:fadeInUp .5s var(--ease-smooth) both}
.how-section h3{font-size:15px;margin-bottom:16px;font-weight:700;letter-spacing:-.01em;color:var(--gn3)}
.flow-diagram{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;
  padding:20px;background:rgba(240,253,244,.5);border-radius:var(--r);margin-bottom:16px;font-size:12px;
  border:1px solid rgba(200,230,200,.4)}
.flow-box{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:12px 18px;
  text-align:center;font-weight:600;transition:all .25s var(--ease-smooth);box-shadow:var(--shadow-sm)}
.flow-box:hover{transform:translateY(-2px);box-shadow:var(--shadow-md)}
.flow-box.highlight{background:linear-gradient(135deg,rgba(21,128,61,.06),rgba(13,148,136,.06));
  border-color:rgba(21,128,61,.2)}
.flow-box.server{background:rgba(245,250,245,.5);border:1.5px dashed rgba(180,210,180,.5);color:#7a937a}
.flow-arrow{color:var(--gn);font-weight:700;font-size:18px}
.how-list{font-size:12px;color:var(--ink2);line-height:2.2}
.how-list li{list-style:none;padding-left:22px;position:relative}
.how-list li::before{content:'';position:absolute;left:0;top:10px;width:8px;height:8px;border-radius:50%}
.how-list .do::before{background:var(--gn);box-shadow:0 0 0 3px rgba(21,128,61,.12)}
.how-list .dont::before{background:var(--rd);box-shadow:0 0 0 3px rgba(220,38,38,.1)}

/* ===== COLUMN CONFIG ===== */
.col-list{border:1px solid var(--bd);border-radius:8px;background:rgba(255,255,255,.5)}
.col-item{display:flex;align-items:center;gap:8px;padding:7px 10px;border-bottom:1px solid rgba(220,240,220,.5);
  font-size:12px;cursor:grab;transition:background .15s}
.col-item:last-child{border:none}
.col-item:hover{background:rgba(21,128,61,.02)}
.col-item .grip{color:#bac8ba;cursor:grab;user-select:none;font-size:14px}
.col-item input[type="checkbox"]{margin:0;accent-color:var(--gn)}
.col-item .col-name{flex:1;font-weight:500}
.col-item .col-del{cursor:pointer;color:#d4d4d8;font-size:15px;padding:0 4px;transition:color .15s;
  display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:6px}
.col-item .col-del:hover{color:var(--rd);background:rgba(220,38,38,.06)}

/* ===== RESPONSIVE ===== */
@media(max-width:768px){
  .tb{height:auto;min-height:48px;flex-wrap:wrap;padding:8px 12px;gap:6px}
  .tb-logo{font-size:14px}
  .tb-logo::before{width:22px;height:22px;border-radius:6px;background-size:14px}
  .tb-sp{flex-basis:100%;height:0}
  .tb-stat{font-size:10px;margin:0 4px;order:1}
  .tb-btn{padding:6px 12px;font-size:11px;order:2}
  .tb-dl{padding:6px 14px;font-size:11px;order:3}
  .wrap{padding:14px 10px 50px}
  .concept{padding:24px 18px;border-radius:14px}
  .concept .hero-title{font-size:20px !important}
  .concept>div:last-child>span{font-size:10px;padding:5px 10px}
  .sec-banner{padding:12px 14px;gap:10px;flex-direction:column}
  .sec-icon{font-size:18px}
  .sec-text{font-size:11px}
  .sum-grid{grid-template-columns:1fr 1fr;gap:8px}
  .sum-card{padding:12px 14px}
  .sum-val{font-size:16px}
  .card{border-radius:10px;margin-bottom:12px}
  .cardh{padding:10px 12px;gap:6px}
  .cardh>div:last-child{width:100%;justify-content:flex-end;margin-top:4px}
  .drop{padding:28px 16px;border-radius:12px}
  .flow-diagram{flex-direction:column;padding:14px}
  .flow-box{padding:8px 14px;font-size:11px}
  .how-section{padding:20px 16px;border-radius:12px}
  table{font-size:11px}
  th{padding:6px 6px;font-size:9px}
  td{padding:5px 6px}
  td input[type="text"],td input[type="number"]{font-size:11px}
  td select{font-size:10px;max-width:100px}
  .modal{max-width:100%;border-radius:12px}
  .modal-bg{padding:20px 8px}
  .modal-body{padding:16px}
  .modal-body h4{font-size:11px}
  .form-row{flex-direction:column;align-items:stretch;gap:4px}
  .form-row label{min-width:auto;font-size:11px}
  .form-row input,.form-row select{padding:8px 10px;font-size:12px}
  .acct-list{max-height:200px}
  .acct-item{padding:5px 8px;font-size:11px}
  .notif{left:10px;right:10px;bottom:12px;text-align:center;border-radius:10px}
}
@media(max-width:480px){
  .tb-logo{font-size:13px}
  .tb-badge{font-size:8px;padding:2px 6px}
  .tb-stat{font-size:9px}
  .tb-btn,.tb-dl{font-size:10px;padding:5px 10px}
  .concept{padding:20px 14px}
  .concept .hero-title{font-size:18px !important}
  .concept>div:last-child>span{font-size:9px;padding:4px 8px}
  .sum-grid{grid-template-columns:1fr}
  .drop{padding:22px 12px}
  .drop>div:nth-child(2){font-size:13px}
  .how-section{padding:16px 12px}
  .how-section h3{font-size:13px}
  .how-list{font-size:11px}
}
</style>
</head>
<body>

<div class="tb">
  <a href="/" class="tb-logo">SmartBooks</a>
  <span class="tb-badge">AI</span>
  <span class="tb-badge" id="provider-badge">未設定</span>
  <div class="tb-sp"></div>
  <span class="tb-stat" id="tb-stat">0件 / &yen;0</span>
  <button class="tb-btn" onclick="openSettings()">設定</button>
  <button class="tb-dl" id="btn-export" onclick="showExportMenu()" disabled>出力</button>
</div>

<div class="wrap">

<!-- SECURITY BANNER -->
<div class="sec-banner">
  <span class="sec-icon">&#128274;</span>
  <div class="sec-text">
    <strong>APIキーはお使いのブラウザ内にのみ保存</strong>されます。API呼び出し時のみサーバーを経由しますが、<strong>データの保存・記録は一切行いません</strong>。
    <span class="sec-badge">データ非保存</span><br>
    <a class="sec-link" onclick="document.getElementById('how-section').scrollIntoView({behavior:'smooth'})">仕組みを詳しく見る</a>
  </div>
</div>

<!-- HERO -->
<div class="concept">
  <div style="font-size:11px;font-weight:600;color:rgba(187,247,208,.85);letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px">AI-Powered Accounting Assistant</div>
  <div class="hero-title" style="font-size:26px;font-weight:700;margin-bottom:6px;line-height:1.35;letter-spacing:-.03em;font-family:'Inter','Noto Sans JP',sans-serif">SmartBooks</div>
  <div style="font-size:14px;font-weight:500;color:rgba(255,255,255,.75);margin-bottom:12px;letter-spacing:.01em">AI経理アシスタント</div>
  <div style="font-size:13px;color:rgba(255,255,255,.55);line-height:1.9;max-width:580px">レシート・領収書のPDFをアップロードするだけ。<br>お手持ちのAI APIキーでOCR読取 &rarr; 自動仕分け &rarr; 会計ソフト用に出力。</div>
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:22px">
    <span style="background:rgba(255,255,255,.08);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.12);border-radius:20px;padding:7px 16px;font-size:11px;color:rgba(255,255,255,.8);font-weight:500;transition:all .2s">1. API設定</span>
    <span style="color:rgba(255,255,255,.2);font-size:14px">&rarr;</span>
    <span style="background:rgba(255,255,255,.08);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.12);border-radius:20px;padding:7px 16px;font-size:11px;color:rgba(255,255,255,.8);font-weight:500;transition:all .2s">2. PDF選択</span>
    <span style="color:rgba(255,255,255,.2);font-size:14px">&rarr;</span>
    <span style="background:rgba(255,255,255,.08);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.12);border-radius:20px;padding:7px 16px;font-size:11px;color:rgba(255,255,255,.8);font-weight:500;transition:all .2s">3. AI OCR+仕分け</span>
    <span style="color:rgba(255,255,255,.2);font-size:14px">&rarr;</span>
    <span style="background:rgba(34,197,94,.35);backdrop-filter:blur(8px);border:1px solid rgba(187,247,208,.35);border-radius:20px;padding:7px 16px;font-size:11px;color:#fff;font-weight:600;box-shadow:0 2px 12px rgba(34,197,94,.25);transition:all .2s">4. CSV/Excel出力</span>
  </div>
</div>

<!-- API KEY WARNING -->
<div class="card" id="api-warning" style="border-color:var(--am);background:var(--ambg)">
  <div style="padding:12px 16px;display:flex;align-items:center;gap:8px">
    <span style="font-size:16px">&#9888;&#65039;</span>
    <span style="font-size:12px;color:var(--am);font-weight:600">AIプロバイダーとAPIキーを設定してください</span>
    <button class="btn btn-sm" style="margin-left:auto;background:var(--am);color:#fff" onclick="openSettings()">設定を開く</button>
  </div>
</div>

<!-- DROP ZONE -->
<div class="drop" id="drop-zone"
  ondragover="event.preventDefault();this.classList.add('dg')"
  ondragleave="this.classList.remove('dg')"
  ondrop="onDrop(event)">
  <input type="file" id="file-input" accept="application/pdf,image/jpeg,image/png" multiple onchange="onFileSelect(this.files)" style="display:none">
  <div style="font-size:36px;margin-bottom:10px;animation:float 3s ease-in-out infinite;opacity:.8">&#128196;</div>
  <div style="font-size:15px;font-weight:700;margin-bottom:6px;color:var(--ink)">レシート・領収書をドラッグ＆ドロップ</div>
  <div style="font-size:11px;color:var(--ink3);display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap">
    <span style="background:rgba(21,128,61,.07);color:var(--gn);padding:2px 10px;border-radius:4px;font-weight:600">PDF</span>
    <span style="background:rgba(21,128,61,.07);color:var(--gn);padding:2px 10px;border-radius:4px;font-weight:600">JPEG</span>
    <span style="background:rgba(21,128,61,.07);color:var(--gn);padding:2px 10px;border-radius:4px;font-weight:600">PNG</span>
    <span style="color:var(--bd2)">|</span>
    <span>複数ファイル可</span>
    <span style="color:var(--bd2)">|</span>
    <span>クリックでファイル選択</span>
  </div>
</div>
<div class="pills" id="file-pills"></div>

<!-- LOADING -->
<div class="ld" id="loading">
  <div class="spin"></div>
  <span class="ld-text" id="ld-text">AI読み取り中...</span>
  <span class="ld-sub" id="ld-sub"></span>
</div>

<!-- RESULTS -->
<div id="results" style="display:none">
  <div class="sum-grid" id="summary-grid"></div>

  <div class="card">
    <div class="cardh">
      <span class="cardt">仕訳一覧</span>
      <span class="chip cb" id="result-count">0件</span>
      <div style="margin-left:auto;display:flex;gap:6px">
        <button class="btn btn-o btn-sm" onclick="addRow()">+ 行追加</button>
        <button class="btn btn-o btn-sm" onclick="copyToClipboard()">クリップボード</button>
        <button class="btn btn-b btn-sm" onclick="downloadCSV()">CSV</button>
        <button class="btn btn-g btn-sm" onclick="downloadExcel()">Excel</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead id="result-thead"></thead>
        <tbody id="result-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- ACCOUNT SUMMARY -->
  <div class="card">
    <div class="cardh"><span class="cardt">勘定科目別集計</span></div>
    <table>
      <thead><tr><th>コード</th><th>勘定科目</th><th>件数</th><th class="ar">合計金額</th></tr></thead>
      <tbody id="acct-summary"></tbody>
    </table>
  </div>
</div>

<!-- EMPTY -->
<div class="empty" id="empty-state">
  <div style="font-size:36px;margin-bottom:10px;opacity:.5;animation:float 4s ease-in-out infinite">&#128203;</div>
  <div style="font-weight:700;font-size:14px;color:var(--ink2);margin-bottom:4px">PDFをアップロードすると仕分け結果が表示されます</div>
  <div style="font-size:11px;color:var(--ink3)">対応形式: PDF / JPEG / PNG</div>
</div>

<!-- HOW IT WORKS -->
<div class="how-section" id="how-section">
  <h3>&#128274; SmartBooksの仕組み</h3>
  <div class="flow-diagram">
    <div class="flow-box highlight">&#128187; あなたのブラウザ<br><small>PDF読取・表示・出力</small></div>
    <span class="flow-arrow">&rarr;</span>
    <div class="flow-box">&#9729;&#65039; このサイトのサーバー<br><small>API中継のみ（データ非保存）</small></div>
    <span class="flow-arrow">&rarr;</span>
    <div class="flow-box highlight">&#129302; AI API（各社）<br><small>OCR + 仕分け処理</small></div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:12px">
    <div>
      <div style="font-size:12px;font-weight:700;color:var(--gn);margin-bottom:4px">&#9989; このサイトのサーバーが行うこと</div>
      <ul class="how-list">
        <li class="do">HTMLページの配信</li>
        <li class="do">AI APIへのリクエスト中継（透過プロキシ）</li>
      </ul>
    </div>
    <div>
      <div style="font-size:12px;font-weight:700;color:var(--rd);margin-bottom:4px">&#10060; このサイトのサーバーが行わないこと</div>
      <ul class="how-list">
        <li class="dont">APIキーの保存・記録</li>
        <li class="dont">レシートデータの保存・記録</li>
        <li class="dont">ログの記録・分析</li>
      </ul>
    </div>
  </div>
</div>

<!-- FOOTER -->
<div style="text-align:center;padding:36px 0 16px;font-size:11px;color:var(--ink3);line-height:2.2;border-top:1px solid rgba(180,210,180,.25);margin-top:24px">
  <div style="font-weight:700;margin-bottom:4px;font-size:12px;color:var(--gn3)">SmartBooks &mdash; AI経理アシスタント</div>
  <div style="margin-bottom:2px">運営: <a href="https://surc.online/" target="_blank" rel="noopener" style="color:var(--gn);text-decoration:none;font-weight:700;transition:color .2s" onmouseover="this.style.color='#22c55e'" onmouseout="this.style.color='var(--gn)'">surc.online</a></div>
  <div style="color:var(--ink3);opacity:.7">APIキーはブラウザのlocalStorageに保存され、サーバーには送信されません。</div>
  <div style="color:var(--ink3);opacity:.7">本ツールによる仕分け結果はAIによる推定です。必ず内容をご確認ください。</div>
</div>

</div><!-- /wrap -->

<!-- EXPORT MENU -->
<div class="modal-bg" id="export-modal">
  <div class="modal" style="max-width:400px">
    <div class="modal-h">
      <h3>出力形式を選択</h3>
      <button class="modal-close" onclick="closeExportMenu()">&times;</button>
    </div>
    <div class="modal-body">
      <h4>出力テンプレート</h4>
      <div class="form-row">
        <select id="export-template" style="width:100%;padding:8px" onchange="saveSettings()">
          <option value="generic">汎用CSV</option>
          <option value="tkc">TKC</option>
          <option value="yayoi">弥生会計</option>
          <option value="freee">freee</option>
          <option value="mf">マネーフォワード</option>
        </select>
      </div>
      <div style="display:flex;gap:10px;margin-top:16px">
        <button class="btn btn-b" style="flex:1;justify-content:center;padding:10px" onclick="downloadCSV();closeExportMenu()">CSV出力</button>
        <button class="btn btn-g" style="flex:1;justify-content:center;padding:10px" onclick="downloadExcel();closeExportMenu()">Excel出力</button>
      </div>
      <div style="margin-top:10px">
        <button class="btn btn-o" style="width:100%;justify-content:center;padding:10px" onclick="copyToClipboard();closeExportMenu()">クリップボードにコピー（スプレッドシート貼付用）</button>
      </div>
    </div>
  </div>
</div>

<!-- SETTINGS MODAL -->
<div class="modal-bg" id="settings-modal">
  <div class="modal">
    <div class="modal-h">
      <h3>&#9881;&#65039; 設定</h3>
      <button class="modal-close" onclick="closeSettings()">&times;</button>
    </div>
    <div class="modal-body">

      <!-- AI Provider -->
      <h4>AIプロバイダー</h4>
      <div class="form-row">
        <label>プロバイダー</label>
        <select id="cfg-provider" onchange="onProviderChange()">
          <option value="claude">Claude (Anthropic)</option>
          <option value="openai">OpenAI (GPT)</option>
        </select>
      </div>
      <div class="form-row">
        <label>APIキー</label>
        <input type="password" id="cfg-apikey" placeholder="APIキーを入力" style="flex:1">
        <button class="btn btn-o btn-sm" onclick="toggleKeyVisibility()" id="btn-toggle-key">表示</button>
      </div>
      <div style="font-size:10px;color:var(--ink3);margin:4px 0 8px 108px;line-height:1.8" id="provider-hint">
        Anthropic ConsoleでAPIキーを取得してください
      </div>
      <div style="font-size:10px;color:var(--ink3);margin:0 0 8px 108px;line-height:1.8;display:none" id="provider-guide">
      </div>
      <div class="form-row">
        <label>モデル</label>
        <select id="cfg-model"></select>
      </div>
      <button class="btn btn-g btn-sm" onclick="testApiKey()" id="btn-test-key" style="margin-left:108px;margin-bottom:12px">接続テスト</button>
      <div id="test-result" style="font-size:11px;margin-left:108px;margin-bottom:8px"></div>

      <!-- Accounts -->
      <h4>勘定科目マスタ <button class="btn btn-o btn-sm" onclick="resetAccounts()" style="margin-left:8px">デフォルトに戻す</button></h4>
      <div class="acct-list" id="acct-list"></div>
      <div style="margin-top:6px;display:flex;gap:6px">
        <input type="text" id="new-acct-code" placeholder="コード" style="width:60px">
        <input type="text" id="new-acct-name" placeholder="科目名" style="flex:1">
        <input type="text" id="new-acct-example" placeholder="該当例" style="flex:1">
        <button class="btn btn-o btn-sm" onclick="addAccount()">追加</button>
      </div>

      <!-- Columns -->
      <h4>表示列カスタマイズ <button class="btn btn-o btn-sm" onclick="resetColumns()" style="margin-left:8px">デフォルトに戻す</button></h4>
      <div class="col-list" id="col-list"></div>
      <div style="margin-top:6px;display:flex;gap:6px">
        <input type="text" id="new-col-name" placeholder="列名を入力" style="flex:1">
        <input type="text" id="new-col-key" placeholder="キー名 (英字)" style="width:100px">
        <button class="btn btn-o btn-sm" onclick="addColumn()">追加</button>
      </div>

      <!-- Export template -->
      <h4>デフォルト出力テンプレート</h4>
      <div class="form-row">
        <label>テンプレート</label>
        <select id="cfg-template" onchange="saveSettings()">
          <option value="generic">汎用CSV</option>
          <option value="tkc">TKC</option>
          <option value="yayoi">弥生会計</option>
          <option value="freee">freee</option>
          <option value="mf">マネーフォワード</option>
        </select>
      </div>

      <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--bd);text-align:right">
        <button class="btn btn-g" style="padding:10px 24px;font-size:13px" onclick="saveAllSettings();closeSettings()">保存して閉じる</button>
      </div>
    </div>
  </div>
</div>

<div class="notif" id="notif"></div>

<script>
// ===== PROVIDER CONFIGS =====
const PROVIDERS = {
  claude: {
    name: 'Claude',
    endpoint: 'https://api.anthropic.com/v1/messages',
    models: [
      {id:'claude-sonnet-4-20250514', name:'Claude Sonnet 4'},
      {id:'claude-haiku-4-20250414', name:'Claude Haiku 4'}
    ],
    hint: 'Anthropic ConsoleでAPIキーを取得してください',
    guide: '<a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener" style="color:var(--cy)">Anthropic Console</a> にログイン → Settings → API Keys → Create Key',
    cost: '入力$3/出力$15 per 1M tokens (Sonnet 4)'
  },
  openai: {
    name: 'OpenAI',
    endpoint: 'https://api.openai.com/v1/chat/completions',
    models: [
      {id:'gpt-4o', name:'GPT-4o'},
      {id:'gpt-4o-mini', name:'GPT-4o mini'}
    ],
    hint: 'OpenAI PlatformでAPIキーを取得してください',
    guide: '<a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener" style="color:var(--cy)">OpenAI Platform</a> にログイン → API Keys → Create new secret key',
    cost: '入力$2.5/出力$10 per 1M tokens (GPT-4o)'
  }
};

// ===== DEFAULT ACCOUNTS =====
const DEFAULT_ACCOUNTS = [
  {code:'510',name:'仕入高',example:'商品仕入'},
  {code:'521',name:'通信費',example:'電話, 郵送, インターネット'},
  {code:'522',name:'旅費交通費',example:'交通費, 出張費, 駐車場'},
  {code:'523',name:'接待交際費',example:'接待, 贈答'},
  {code:'524',name:'消耗品費',example:'文具, 日用品, 備品'},
  {code:'525',name:'水道光熱費',example:'電気, ガス, 水道'},
  {code:'526',name:'修繕費',example:'修理, メンテナンス'},
  {code:'527',name:'地代家賃',example:'事務所家賃, 駐車場'},
  {code:'528',name:'保険料',example:'各種保険'},
  {code:'529',name:'支払手数料',example:'振込手数料, 各種手数料'},
  {code:'530',name:'車両費',example:'ガソリン, 車検, 車両整備'},
  {code:'531',name:'広告宣伝費',example:'広告, 販促費'},
  {code:'532',name:'会議費',example:'打ち合わせ飲食'},
  {code:'540',name:'福利厚生費',example:'社員向け福利'},
  {code:'550',name:'新聞図書費',example:'新聞, 書籍, 購読料'},
  {code:'560',name:'リース料',example:'リース'},
  {code:'590',name:'雑費',example:'その他'}
];

// ===== DEFAULT COLUMNS =====
const DEFAULT_COLUMNS = [
  {key:'date', name:'日付', enabled:true, custom:false},
  {key:'vendor', name:'店名/取引先', enabled:true, custom:false},
  {key:'account_code', name:'勘定科目', enabled:true, custom:false},
  {key:'total', name:'金額', enabled:true, custom:false},
  {key:'tax_category', name:'税区分', enabled:true, custom:false},
  {key:'sub_account', name:'補助科目', enabled:true, custom:false},
  {key:'memo', name:'摘要', enabled:true, custom:false}
];

const TAX_CATEGORIES = [
  '課税仕入10%','課税仕入8%（軽減）','非課税仕入','不課税仕入','対象外'
];

// ===== STATE =====
let config = {
  provider: 'claude',
  apiKey: '',
  model: '',
  template: 'generic',
  accounts: JSON.parse(JSON.stringify(DEFAULT_ACCOUNTS)),
  columns: JSON.parse(JSON.stringify(DEFAULT_COLUMNS))
};
let allReceipts = [];
let fileQueue = [];

// ===== INIT =====
function init() {
  loadSettings();
  updateProviderBadge();
  updateApiWarning();
  renderAccountList();
  renderColumnList();
  renderResults();
}

// ===== SETTINGS PERSISTENCE =====
function loadSettings() {
  try {
    const saved = localStorage.getItem('ocr-public-config');
    if (saved) {
      const parsed = JSON.parse(saved);
      config = {...config, ...parsed};
      if (!config.accounts || !config.accounts.length) config.accounts = JSON.parse(JSON.stringify(DEFAULT_ACCOUNTS));
      if (!config.columns || !config.columns.length) config.columns = JSON.parse(JSON.stringify(DEFAULT_COLUMNS));
      // If saved provider no longer exists in PROVIDERS (e.g. removed provider), reset to default
      if (!PROVIDERS[config.provider]) config.provider = Object.keys(PROVIDERS)[0];
    }
  } catch(e) {}
  // Apply to UI
  document.getElementById('cfg-provider').value = config.provider;
  document.getElementById('cfg-apikey').value = config.apiKey;
  document.getElementById('cfg-template').value = config.template;
  document.getElementById('export-template').value = config.template;
  onProviderChange(true);
}

function saveSettings() {
  config.provider = document.getElementById('cfg-provider').value;
  config.apiKey = document.getElementById('cfg-apikey').value;
  config.model = document.getElementById('cfg-model').value;
  config.template = document.getElementById('cfg-template').value;
  document.getElementById('export-template').value = config.template;
  localStorage.setItem('ocr-public-config', JSON.stringify(config));
  updateProviderBadge();
  updateApiWarning();
}

function saveAllSettings() {
  // Also save accounts and columns from current state
  saveSettings();
  notify('設定を保存しました');
}

function updateProviderBadge() {
  const badge = document.getElementById('provider-badge');
  if (config.apiKey) {
    badge.textContent = PROVIDERS[config.provider]?.name || config.provider;
    badge.style.background = 'rgba(255,255,255,.2)';
  } else {
    badge.textContent = '未設定';
    badge.style.background = '';
  }
}

function updateApiWarning() {
  document.getElementById('api-warning').style.display = config.apiKey ? 'none' : '';
}

// ===== SETTINGS MODAL =====
function openSettings() {
  document.getElementById('cfg-provider').value = config.provider;
  document.getElementById('cfg-apikey').value = config.apiKey;
  document.getElementById('cfg-template').value = config.template;
  onProviderChange(true);
  renderAccountList();
  renderColumnList();
  document.getElementById('settings-modal').classList.add('on');
}

function closeSettings() {
  document.getElementById('settings-modal').classList.remove('on');
}

function onProviderChange(skipSave) {
  let provider = document.getElementById('cfg-provider').value;
  // Guard: if saved provider no longer exists (e.g. removed provider), fall back to first available
  if (!PROVIDERS[provider]) {
    provider = Object.keys(PROVIDERS)[0];
    document.getElementById('cfg-provider').value = provider;
    config.provider = provider;
  }
  const p = PROVIDERS[provider];
  const modelSelect = document.getElementById('cfg-model');
  modelSelect.innerHTML = p.models.map(m =>
    '<option value="' + m.id + '">' + m.name + '</option>'
  ).join('');
  document.getElementById('provider-hint').textContent = p.hint;
  // Show guide with link and cost info
  const guideEl = document.getElementById('provider-guide');
  if (p.guide) {
    guideEl.innerHTML = '&#128279; ' + p.guide + '<br>&#128176; ' + escH(p.cost);
    guideEl.style.display = '';
  } else {
    guideEl.style.display = 'none';
  }
  // Restore saved model if applicable
  if (config.provider === provider && config.model) {
    modelSelect.value = config.model;
  }
  if (!skipSave) saveSettings();
}

function toggleKeyVisibility() {
  const input = document.getElementById('cfg-apikey');
  const btn = document.getElementById('btn-toggle-key');
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '隠す';
  } else {
    input.type = 'password';
    btn.textContent = '表示';
  }
}

async function testApiKey() {
  const provider = document.getElementById('cfg-provider').value;
  const apiKey = document.getElementById('cfg-apikey').value;
  const model = document.getElementById('cfg-model').value;
  const resultEl = document.getElementById('test-result');

  if (!apiKey) {
    resultEl.innerHTML = '<span style="color:var(--rd)">APIキーを入力してください</span>';
    return;
  }

  resultEl.innerHTML = '<span style="color:var(--gn)">テスト中...</span>';
  document.getElementById('btn-test-key').disabled = true;

  try {
    const testPrompt = 'Say "OK" in one word.';
    const resp = await callAI(provider, apiKey, model, [{type:'text',text:testPrompt}], null);
    resultEl.innerHTML = '<span style="color:var(--gn)">&#9989; 接続成功</span>';
    saveSettings();
  } catch(e) {
    let msg = e.message;
    if (msg === 'Failed to fetch' || msg.includes('NetworkError')) {
      msg += '（ネットワークエラー: CORSブロックまたは接続不可。ブラウザのDevTools > Consoleでエラー詳細を確認してください）';
    }
    resultEl.innerHTML = '<span style="color:var(--rd)">&#10060; ' + escH(msg) + '</span>';
  } finally {
    document.getElementById('btn-test-key').disabled = false;
  }
}

// ===== ACCOUNT MANAGEMENT =====
function renderAccountList() {
  const el = document.getElementById('acct-list');
  el.innerHTML = config.accounts.map((a, i) =>
    '<div class="acct-item">' +
    '<input type="text" value="' + escH(a.code) + '" style="width:50px" onchange="config.accounts['+i+'].code=this.value;saveSettings()">' +
    '<input type="text" value="' + escH(a.name) + '" onchange="config.accounts['+i+'].name=this.value;saveSettings()">' +
    '<input type="text" value="' + escH(a.example||'') + '" placeholder="該当例" style="color:var(--ink3)" onchange="config.accounts['+i+'].example=this.value;saveSettings()">' +
    '<span class="acct-del" onclick="config.accounts.splice('+i+',1);renderAccountList();saveSettings()">&times;</span>' +
    '</div>'
  ).join('');
}

function addAccount() {
  const code = document.getElementById('new-acct-code').value.trim();
  const name = document.getElementById('new-acct-name').value.trim();
  const example = document.getElementById('new-acct-example').value.trim();
  if (!code || !name) { notify('コードと科目名を入力してください', true); return; }
  config.accounts.push({code, name, example});
  document.getElementById('new-acct-code').value = '';
  document.getElementById('new-acct-name').value = '';
  document.getElementById('new-acct-example').value = '';
  renderAccountList();
  saveSettings();
}

function resetAccounts() {
  config.accounts = JSON.parse(JSON.stringify(DEFAULT_ACCOUNTS));
  renderAccountList();
  saveSettings();
  notify('勘定科目をデフォルトに戻しました');
}

// ===== COLUMN MANAGEMENT =====
function renderColumnList() {
  const el = document.getElementById('col-list');
  el.innerHTML = config.columns.map((c, i) =>
    '<div class="col-item" draggable="true" ondragstart="colDragStart(event,'+i+')" ondragover="event.preventDefault()" ondrop="colDrop(event,'+i+')">' +
    '<span class="grip">&#9776;</span>' +
    '<input type="checkbox" ' + (c.enabled?'checked':'') + ' onchange="config.columns['+i+'].enabled=this.checked;saveSettings();renderResultHeaders()">' +
    '<span class="col-name">' + escH(c.name) + '</span>' +
    (c.custom ? '<span class="col-del" onclick="config.columns.splice('+i+',1);renderColumnList();saveSettings();renderResults()">&times;</span>' : '') +
    '</div>'
  ).join('');
}

let dragColIdx = -1;
function colDragStart(e, i) { dragColIdx = i; e.dataTransfer.effectAllowed = 'move'; }
function colDrop(e, i) {
  e.preventDefault();
  if (dragColIdx < 0 || dragColIdx === i) return;
  const item = config.columns.splice(dragColIdx, 1)[0];
  config.columns.splice(i, 0, item);
  dragColIdx = -1;
  renderColumnList();
  saveSettings();
  renderResults();
}

function addColumn() {
  const name = document.getElementById('new-col-name').value.trim();
  const key = document.getElementById('new-col-key').value.trim() || name;
  if (!name) { notify('列名を入力してください', true); return; }
  config.columns.push({key: 'custom_' + key.replace(/[^a-zA-Z0-9_]/g,''), name, enabled: true, custom: true});
  document.getElementById('new-col-name').value = '';
  document.getElementById('new-col-key').value = '';
  renderColumnList();
  saveSettings();
  renderResults();
}

function resetColumns() {
  config.columns = JSON.parse(JSON.stringify(DEFAULT_COLUMNS));
  renderColumnList();
  saveSettings();
  renderResults();
  notify('列設定をデフォルトに戻しました');
}

// ===== PDF TO IMAGES =====
pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

async function pdfToImages(file) {
  const arrayBuf = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({data: new Uint8Array(arrayBuf)}).promise;
  const images = [];
  const scale = 2.0;
  if (pdf.numPages > 30) {
    throw new Error('PDFが' + pdf.numPages + 'ページあります。30ページ以内にしてください');
  }
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const vp = page.getViewport({scale});
    const canvas = document.createElement('canvas');
    canvas.width = vp.width;
    canvas.height = vp.height;
    const ctx = canvas.getContext('2d');
    await page.render({canvasContext: ctx, viewport: vp}).promise;
    const dataUrl = canvas.toDataURL('image/png');
    images.push({data: dataUrl.split(',')[1], mediaType: 'image/png'});
  }
  return images;
}

// ===== AI API CALLS =====
function buildSystemPrompt() {
  let prompt = 'あなたは日本の経理処理の専門家です。レシートや領収書の画像を読み取り、仕訳データを作成してください。\\n\\n';
  prompt += '## 勘定科目マスタ\\n| コード | 科目名 | 該当例 |\\n|--------|--------|--------|\\n';
  for (const a of config.accounts) {
    prompt += '| ' + a.code + ' | ' + a.name + ' | ' + (a.example||'') + ' |\\n';
  }
  prompt += '\\n## 仕分けルール\\n';
  prompt += '- 税率は10%が基本、食品は軽減税率8%を考慮\\n';
  prompt += '- インボイス番号（T始まり13桁）があれば記録\\n';
  prompt += '- 1ページに複数レシートが貼り付けられている場合あり、すべて個別に読み取ること\\n';

  // Custom columns instruction
  const customCols = config.columns.filter(c => c.enabled && c.custom);
  if (customCols.length) {
    prompt += '\\n## 追加列\\n以下の列も可能な限りレシートから読み取って埋めてください:\\n';
    for (const c of customCols) {
      prompt += '- ' + c.name + ' (キー: ' + c.key + ')\\n';
    }
  }

  prompt += '\\n## 出力形式\\n以下のJSON形式で返してください。必ずJSONのみを返し、説明文は不要です。\\n\`\`\`json\\n{\\n  "receipts": [\\n    {\\n';
  prompt += '      "date": "2026-04-28",\\n';
  prompt += '      "vendor": "店名",\\n';
  prompt += '      "account_code": "524",\\n';
  prompt += '      "account_name": "消耗品費",\\n';
  prompt += '      "total": 550,\\n';
  prompt += '      "tax_category": "課税仕入10%",\\n';
  prompt += '      "sub_account": "",\\n';
  prompt += '      "memo": "品名の概要"';
  if (customCols.length) {
    for (const c of customCols) {
      prompt += ',\\n      "' + c.key + '": ""';
    }
  }
  prompt += '\\n    }\\n  ]\\n}\\n\`\`\`';
  return prompt;
}

async function callAI(provider, apiKey, model, content, systemPrompt) {
  // All API calls go through Worker proxy to avoid CORS issues
  const resp = await fetch('/api/proxy', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({provider, apiKey, model, content, systemPrompt, maxTokens: 8192})
  });

  const data = await resp.json();

  if (!resp.ok) {
    // Extract error message from API response
    const msg = data?.error?.message || data?.error || 'API エラー (' + resp.status + ')';
    throw new Error(msg);
  }

  // Parse response based on provider
  if (provider === 'claude') {
    const textBlock = data.content?.find(b => b.type === 'text');
    if (!textBlock) throw new Error('応答テキストがありません');
    return textBlock.text;
  } else if (provider === 'openai') {
    return data.choices?.[0]?.message?.content || '';
  }

  throw new Error('未対応のプロバイダー: ' + provider);
}

function parseAIResponse(text) {
  let jsonStr = text.trim();
  const jsonMatch = jsonStr.match(/\`\`\`(?:json)?\\s*([\\s\\S]*?)\`\`\`/);
  if (jsonMatch) jsonStr = jsonMatch[1].trim();
  // Try to find JSON object
  const objMatch = jsonStr.match(/\\{[\\s\\S]*\\}/);
  if (objMatch) jsonStr = objMatch[0];
  return JSON.parse(jsonStr);
}

// ===== FILE TO IMAGES =====
const ACCEPTED_TYPES = ['application/pdf', 'image/jpeg', 'image/png'];

async function fileToImages(file) {
  if (file.type === 'application/pdf') {
    return await pdfToImages(file);
  }
  // JPEG or PNG: convert to base64
  const arrayBuf = await file.arrayBuffer();
  const uint8 = new Uint8Array(arrayBuf);
  let binary = '';
  for (let i = 0; i < uint8.length; i++) binary += String.fromCharCode(uint8[i]);
  const base64 = btoa(binary);
  return [{data: base64, mediaType: file.type}];
}

// ===== DRAG & DROP =====
function onDrop(e) {
  e.preventDefault();
  e.currentTarget.classList.remove('dg');
  const files = Array.from(e.dataTransfer.files).filter(f => ACCEPTED_TYPES.includes(f.type));
  if (files.length) processFiles(files);
}

function onFileSelect(fileList) {
  const files = Array.from(fileList).filter(f => ACCEPTED_TYPES.includes(f.type));
  if (files.length) processFiles(files);
  document.getElementById('file-input').value = '';
}

document.getElementById('drop-zone').addEventListener('click', function(e) {
  if (e.target === this || e.target.parentElement === this) {
    document.getElementById('file-input').click();
  }
});

function showPills() {
  const el = document.getElementById('file-pills');
  el.innerHTML = fileQueue.map((f) =>
    '<div class="pill"><span>' + escH(f.name) + '</span> <span class="chip ' +
    (f.status==='done'?'cg':f.status==='processing'?'ca':f.status==='error'?'':'' ) + '">' +
    (f.status==='done'?'完了':f.status==='processing'?'処理中':f.status==='error'?'エラー':'待機') +
    '</span></div>'
  ).join('');
}

// ===== PROCESS =====
async function processFiles(files) {
  if (!config.apiKey) {
    notify('先にAPIキーを設定してください', true);
    openSettings();
    return;
  }

  try {
    for (const f of files) {
      if (!fileQueue.find(q => q.name === f.name)) {
        fileQueue.push({name: f.name, file: f, status: 'pending'});
      }
    }
    showPills();
    document.getElementById('drop-zone').classList.add('processing');
    document.getElementById('loading').classList.add('on');
    document.getElementById('empty-state').style.display = 'none';

    for (const item of fileQueue) {
      if (item.status !== 'pending') continue;
      item.status = 'processing';
      showPills();
      document.getElementById('ld-text').textContent = item.name + ' を処理中...';
      document.getElementById('ld-sub').textContent = '';

      try {
        const images = await fileToImages(item.file);
        document.getElementById('ld-text').textContent = 'AI読み取り中... (' + images.length + '枚)';
        document.getElementById('ld-sub').textContent = PROVIDERS[config.provider]?.name || '';

        // Build content
        const content = [];
        for (const img of images) {
          content.push({
            type: 'image',
            source: { type: 'base64', media_type: img.mediaType, data: img.data }
          });
        }
        content.push({
          type: 'text',
          text: 'これらのレシート・領収書画像を読み取り、仕訳データをJSON形式で返してください。\\n画像にレシートが複数枚写っている場合は、すべて個別に読み取ってください。'
        });

        const systemPrompt = buildSystemPrompt();
        const responseText = await callAI(config.provider, config.apiKey, config.model, content, systemPrompt);
        const result = parseAIResponse(responseText);

        if (result.receipts && result.receipts.length > 0) {
          allReceipts = allReceipts.concat(result.receipts);
        }
        item.status = 'done';
        notify(item.name + ': ' + (result.receipts?.length || 0) + '件検出');
      } catch (err) {
        item.status = 'error';
        notify(item.name + ': エラー - ' + err.message, true);
      }
      showPills();
    }
  } catch (outerErr) {
    notify('処理エラー: ' + outerErr.message, true);
  } finally {
    document.getElementById('loading').classList.remove('on');
    document.getElementById('drop-zone').classList.remove('processing');
  }
  renderResults();
}

// ===== RENDER =====
function escH(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtYen(n) { return '\\u00a5' + Number(n||0).toLocaleString(); }

function getEnabledColumns() {
  return config.columns.filter(c => c.enabled);
}

function accountOptions(selected) {
  return config.accounts.map(a =>
    '<option value="' + escH(a.code) + '"' + (a.code===selected?' selected':'') + '>' + escH(a.code) + ' ' + escH(a.name) + '</option>'
  ).join('');
}

function taxOptions(selected) {
  return TAX_CATEGORIES.map(t =>
    '<option value="' + escH(t) + '"' + (t===selected?' selected':'') + '>' + escH(t) + '</option>'
  ).join('');
}

function renderResultHeaders() {
  const cols = getEnabledColumns();
  document.getElementById('result-thead').innerHTML = '<tr>' +
    '<th style="width:30px"></th>' +
    cols.map(c => '<th' + (c.key==='total'?' class="ar"':'') + '>' + escH(c.name) + '</th>').join('') +
    '<th style="width:28px"></th>' +
    '</tr>';
}

function renderCellHtml(r, col, i) {
  const key = col.key;
  if (key === 'date') return '<input type="text" value="' + escH(r.date||'') + '" onchange="upd('+i+',\\'date\\',this.value)">';
  if (key === 'vendor') return '<input type="text" value="' + escH(r.vendor||'') + '" onchange="upd('+i+',\\'vendor\\',this.value)" style="min-width:100px">';
  if (key === 'account_code') return '<select onchange="upd('+i+',\\'account_code\\',this.value);updAcctName('+i+')">' + accountOptions(r.account_code) + '</select>';
  if (key === 'total') return '<input type="number" value="' + Number(r.total||0) + '" onchange="upd('+i+',\\'total\\',Number(this.value));renderSummaries()" style="width:80px;text-align:right">';
  if (key === 'tax_category') return '<select onchange="upd('+i+',\\'tax_category\\',this.value)">' + taxOptions(r.tax_category) + '</select>';
  if (key === 'sub_account') return '<input type="text" value="' + escH(r.sub_account||'') + '" onchange="upd('+i+',\\'sub_account\\',this.value)">';
  if (key === 'memo') return '<input type="text" value="' + escH(r.memo||r.items||'') + '" onchange="upd('+i+',\\'memo\\',this.value)" style="min-width:120px">';
  // Custom column
  return '<input type="text" value="' + escH(r[key]||'') + '" onchange="upd('+i+',\\'' + escH(key) + '\\',this.value)">';
}

function renderResults() {
  document.getElementById('results').style.display = allReceipts.length ? '' : 'none';
  document.getElementById('empty-state').style.display = allReceipts.length ? 'none' : '';
  document.getElementById('btn-export').disabled = !allReceipts.length;

  const cols = getEnabledColumns();
  renderResultHeaders();

  const tbody = document.getElementById('result-tbody');
  tbody.innerHTML = allReceipts.map((r, i) => {
    return '<tr>' +
    '<td style="color:#bac8ba;font-size:10px;font-family:monospace">' + (i+1) + '</td>' +
    cols.map(c => '<td' + (c.key==='total'?' class="ar"':'') + '>' + renderCellHtml(r, c, i) + '</td>').join('') +
    '<td><span class="del-row" onclick="delRow('+i+')">&times;</span></td>' +
    '</tr>';
  }).join('');

  renderSummaries();
}

function renderSummaries() {
  const total = allReceipts.reduce((s,r) => s + Number(r.total||0), 0);
  document.getElementById('tb-stat').textContent = allReceipts.length + '件 / ' + fmtYen(total);
  document.getElementById('result-count').textContent = allReceipts.length + '件';

  const grid = document.getElementById('summary-grid');
  grid.innerHTML =
    '<div class="sum-card"><div class="sum-lbl">総件数</div><div class="sum-val">' + allReceipts.length + '件</div></div>' +
    '<div class="sum-card"><div class="sum-lbl">合計金額</div><div class="sum-val">' + fmtYen(total) + '</div></div>';

  // Account summary
  const acctMap = {};
  allReceipts.forEach(r => {
    const key = r.account_code || '???';
    if (!acctMap[key]) acctMap[key] = {code: key, name: r.account_name||'', count:0, total:0};
    acctMap[key].count++;
    acctMap[key].total += Number(r.total||0);
  });
  const acctRows = Object.values(acctMap).sort((a,b) => a.code.localeCompare(b.code));
  document.getElementById('acct-summary').innerHTML = acctRows.map(a =>
    '<tr><td>' + escH(a.code) + '</td><td>' + escH(a.name) + '</td><td>' + a.count + '</td><td class="ar">' + fmtYen(a.total) + '</td></tr>'
  ).join('') + '<tr style="font-weight:700;background:rgba(240,253,244,.5)"><td></td><td>合計</td><td>' + allReceipts.length + '</td><td class="ar">' + fmtYen(total) + '</td></tr>';
}

// ===== EDIT =====
function upd(i, key, val) { allReceipts[i][key] = val; }
function updAcctName(i) {
  const code = allReceipts[i].account_code;
  const acct = config.accounts.find(a => a.code === code);
  if (acct) allReceipts[i].account_name = acct.name;
  renderSummaries();
}

function delRow(i) {
  allReceipts.splice(i, 1);
  renderResults();
}

function addRow() {
  const defaultAcct = config.accounts[config.accounts.length-1] || {code:'590',name:'雑費'};
  allReceipts.push({
    date: new Date().toISOString().slice(0,10),
    vendor: '',
    items: '',
    total: 0,
    account_code: defaultAcct.code,
    account_name: defaultAcct.name,
    sub_account: '',
    tax_category: '課税仕入10%',
    memo: ''
  });
  renderResults();
  const tbody = document.getElementById('result-tbody');
  tbody.lastElementChild?.scrollIntoView({behavior:'smooth'});
}

// ===== EXPORT =====
function showExportMenu() {
  document.getElementById('export-modal').classList.add('on');
}
function closeExportMenu() {
  document.getElementById('export-modal').classList.remove('on');
}

function getExportData() {
  const template = document.getElementById('export-template').value;
  return formatForTemplate(template);
}

function formatForTemplate(template) {
  if (template === 'tkc') {
    const headers = ['日付','借方科目コード','借方科目名','借方金額','借方税区分','貸方科目コード','貸方科目名','貸方金額','貸方税区分','摘要'];
    const rows = allReceipts.map(r => [
      r.date||'', r.account_code||'', r.account_name||'', Number(r.total||0),
      r.tax_category||'', '', '', Number(r.total||0), '', (r.vendor||'') + ' ' + (r.memo||r.items||'')
    ]);
    return {headers, rows};
  }
  if (template === 'yayoi') {
    const headers = ['識別フラグ','伝票No.','決算','取引日付','借方勘定科目','借方補助科目','借方部門','借方税区分','借方金額','借方税金額','貸方勘定科目','貸方補助科目','貸方部門','貸方税区分','貸方金額','貸方税金額','摘要','番号','期日','タイプ','生成元','仕訳メモ','付箋1','付箋2','調整'];
    const rows = allReceipts.map((r, i) => [
      2000, i+1, '', r.date||'', r.account_name||'', r.sub_account||'', '', r.tax_category||'',
      Number(r.total||0), '', '現金', '', '', '対象外', Number(r.total||0), '',
      (r.vendor||'') + ' ' + (r.memo||r.items||''), '', '', 0, '', '', 0, 0, 'NO'
    ]);
    return {headers, rows};
  }
  if (template === 'freee') {
    const headers = ['収支区分','管理番号','発生日','決済期日','取引先','勘定科目','税区分','金額','税計算区分','税額','備考','品目','部門','メモタグ','セグメント1','セグメント2','セグメント3'];
    const rows = allReceipts.map(r => [
      '支出', '', r.date||'', '', r.vendor||'', r.account_name||'', r.tax_category||'',
      Number(r.total||0), '', '', r.memo||r.items||'', '', r.sub_account||'', '', '', '', ''
    ]);
    return {headers, rows};
  }
  if (template === 'mf') {
    const headers = ['取引日','借方勘定科目','借方補助科目','借方税区分','借方金額(税込)','貸方勘定科目','貸方補助科目','貸方税区分','貸方金額(税込)','摘要'];
    const rows = allReceipts.map(r => [
      r.date||'', r.account_name||'', r.sub_account||'', r.tax_category||'',
      Number(r.total||0), '現金', '', '対象外', Number(r.total||0),
      (r.vendor||'') + ' ' + (r.memo||r.items||'')
    ]);
    return {headers, rows};
  }
  // Generic
  const cols = getEnabledColumns();
  const headers = cols.map(c => c.name);
  const rows = allReceipts.map(r => cols.map(c => {
    if (c.key === 'total') return Number(r.total||0);
    if (c.key === 'account_code') return (r.account_code||'') + ' ' + (r.account_name||'');
    return r[c.key] || '';
  }));
  return {headers, rows};
}

function downloadCSV() {
  if (!allReceipts.length) return;
  const {headers, rows} = getExportData();
  const bom = '\\uFEFF';
  const csvContent = [headers, ...rows].map(row =>
    row.map(cell => '"' + String(cell).replace(/"/g,'""') + '"').join(',')
  ).join('\\n');

  const blob = new Blob([bom + csvContent], {type:'text/csv;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const template = document.getElementById('export-template').value;
  const now = new Date();
  const dateStr = now.getFullYear() + ('0'+(now.getMonth()+1)).slice(-2) + ('0'+now.getDate()).slice(-2);
  a.href = url;
  a.download = 'SmartBooks_' + template + '_' + dateStr + '.csv';
  a.click();
  URL.revokeObjectURL(url);
  notify('CSV出力完了');
}

function downloadExcel() {
  if (!allReceipts.length) return;
  const {headers, rows} = getExportData();

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
  ws['!cols'] = headers.map(() => ({wch:14}));
  XLSX.utils.book_append_sheet(wb, ws, '仕訳一覧');

  // Account summary sheet
  const acctMap = {};
  allReceipts.forEach(r => {
    const key = r.account_code || '???';
    if (!acctMap[key]) acctMap[key] = {code:key, name:r.account_name||'', count:0, total:0};
    acctMap[key].count++;
    acctMap[key].total += Number(r.total||0);
  });
  const acctData = Object.values(acctMap).sort((a,b) => a.code.localeCompare(b.code));
  const ws2 = XLSX.utils.aoa_to_sheet([
    ['科目コード','科目名','件数','合計金額'],
    ...acctData.map(a => [a.code, a.name, a.count, a.total])
  ]);
  XLSX.utils.book_append_sheet(wb, ws2, '科目別集計');

  const now = new Date();
  const template = document.getElementById('export-template').value;
  const dateStr = now.getFullYear() + ('0'+(now.getMonth()+1)).slice(-2) + ('0'+now.getDate()).slice(-2);
  XLSX.writeFile(wb, 'SmartBooks_' + template + '_' + dateStr + '.xlsx');
  notify('Excel出力完了');
}

function copyToClipboard() {
  if (!allReceipts.length) return;
  const {headers, rows} = getExportData();
  const tsvContent = [headers, ...rows].map(row => row.map(String).join('\\t')).join('\\n');
  navigator.clipboard.writeText(tsvContent).then(() => {
    notify('クリップボードにコピーしました（スプレッドシートに貼り付けできます）');
  }).catch(() => {
    notify('コピーに失敗しました', true);
  });
}

// ===== NOTIFY =====
function notify(msg, isErr) {
  const el = document.getElementById('notif');
  el.textContent = msg;
  el.className = 'notif on' + (isErr ? ' err' : '');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.className = 'notif', 3000);
}

// ===== START =====
init();
</script>
</body>
</html>
`;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Proxy AI API requests - forwards request as-is, stores nothing
async function handleProxy(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResp({ error: 'Invalid JSON' }, 400);
  }

  const { provider, apiKey, model, content, systemPrompt, maxTokens } = body;
  if (!provider || !apiKey) {
    return jsonResp({ error: 'provider and apiKey are required' }, 400);
  }

  try {
    let resp;

    if (provider === 'claude') {
      const reqBody = {
        model: model || 'claude-sonnet-4-20250514',
        max_tokens: maxTokens || 8192,
        messages: [{ role: 'user', content }],
      };
      if (systemPrompt) reqBody.system = systemPrompt;

      resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(reqBody),
      });

    } else if (provider === 'openai') {
      const messages = [];
      if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
      // Convert image content for OpenAI format
      const userContent = content.map(c => {
        if (c.type === 'image') {
          return { type: 'image_url', image_url: { url: 'data:' + (c.source.media_type || 'image/png') + ';base64,' + c.source.data } };
        }
        return c;
      });
      messages.push({ role: 'user', content: userContent });

      resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + apiKey,
        },
        body: JSON.stringify({ model: model || 'gpt-4o', messages, max_tokens: maxTokens || 8192 }),
      });

    } else {
      return jsonResp({ error: 'Unsupported provider: ' + provider }, 400);
    }

    // Forward the API response as-is
    const data = await resp.json();
    return jsonResp(data, resp.status);

  } catch (err) {
    return jsonResp({ error: 'Proxy error: ' + err.message }, 502);
  }
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // AI API proxy
    if (url.pathname === '/api/proxy' && request.method === 'POST') {
      return handleProxy(request);
    }

    // Favicon
    if (url.pathname === '/favicon.ico') {
      return new Response(null, { status: 204 });
    }

    // Serve HTML
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return new Response(HTML_CONTENT, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
