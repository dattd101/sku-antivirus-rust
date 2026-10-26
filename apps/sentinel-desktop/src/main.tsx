import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import { ShieldCheck, ScanSearch, FolderOpen, AlertTriangle, Terminal, Activity } from 'lucide-react';
import './style.css';

type Detection = { path: string; sha256: string };
type ScanReport = { scanned_files: number; detected_files: number; errors: string[]; detections: Detection[]; elapsed_ms: number };
function App() {
  const [folder, setFolder] = useState('C:\\Users\\Public\\Downloads');
  const [signaturePath, setSignaturePath] = useState('');
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState('');
  async function scan() {
    if (!folder.trim()) { setError('Vui lòng nhập thư mục cần quét.'); return; }
    setBusy(true); setError(''); setReport(null);
    try { setReport(await invoke<ScanReport>('scan_folder', { folder: folder.trim(), signaturePath: signaturePath.trim() || null })); }
    catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }
  return <div className="app">
    <aside className="sidebar"><div className="brand"><ShieldCheck size={30}/><span>Sentinel<span className="accent">AV</span></span></div>
      <div className="nav active"><Activity size={18}/> Tổng quan</div><div className="nav"><ScanSearch size={18}/> Quét thủ công</div>
      <div className="sidebottom">Rust + Tauri 2<br/><small>Desktop MVP · v0.2.0</small></div>
    </aside>
    <main><div className="top"><div><div className="eyebrow">ENDPOINT SECURITY</div><h1>Bảng điều khiển</h1><p>Quét file trên Windows bằng chữ ký SHA-256.</p></div><span className="pill">● Scanner MVP</span></div>
      <section className="notice"><AlertTriangle size={22}/><div><b>Chưa có bảo vệ thời gian thực</b><p>Ứng dụng này chỉ quét thủ công; không thay thế Microsoft Defender hoặc antivirus hiện tại.</p></div></section>
      <section className="grid"><div className="stat"><span>File đã quét</span><strong>{report?.scanned_files ?? '—'}</strong></div><div className="stat"><span>Khớp chữ ký</span><strong className="red">{report?.detected_files ?? '—'}</strong></div><div className="stat"><span>Thời gian</span><strong>{report ? `${(report.elapsed_ms / 1000).toFixed(2)}s` : '—'}</strong></div></section>
      <section className="panel"><h2><FolderOpen size={20}/> Quét thư mục</h2><label>Đường dẫn thư mục Windows</label><input value={folder} onChange={e=>setFolder(e.target.value)} placeholder="C:\Users\Public\Downloads" disabled={busy}/>
        <label>Đường dẫn signatures.txt (tùy chọn)</label><input value={signaturePath} onChange={e=>setSignaturePath(e.target.value)} placeholder="Để trống để dùng danh sách tích hợp (rỗng)" disabled={busy}/>
        <p className="hint">Mỗi dòng của signatures.txt là một SHA-256 đã xác minh. Danh sách mặc định không chứa chữ ký malware.</p>
        <button disabled={busy} onClick={scan}><ScanSearch size={18}/>{busy ? 'Đang quét, vui lòng đợi…' : 'Bắt đầu quét'}</button>
        {error && <div className="error">{error}</div>}
      </section>
      {report && <section className="panel"><h2><Terminal size={20}/> Kết quả quét</h2><p>Đã quét {report.scanned_files} file; {report.detected_files} khớp chữ ký; {report.errors.length} lỗi đọc.</p>
        {report.detections.length===0 && <p className="hint">Không có hash trùng chữ ký. Điều này KHÔNG xác nhận file an toàn.</p>}
        {report.detections.map((d,i)=><div className="finding" key={i}><b>{d.path}</b><code>{d.sha256}</code></div>)}
        {report.errors.slice(0,30).map((e,i)=><div className="error" key={i}>{e}</div>)}
        {report.errors.length>30 && <p className="hint">Còn {report.errors.length-30} lỗi khác chưa hiển thị.</p>}
      </section>}
      <footer>SentinelAV · On-demand signature scanner · Không tự động xóa hoặc cách ly file.</footer>
    </main></div>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
