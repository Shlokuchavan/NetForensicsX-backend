export function AmbientBackdrop() {
  return (
    <div aria-hidden className="nfx-backdrop">
      <div className="nfx-backdrop__layer nfx-backdrop__layer--cyan" />
      <div className="nfx-backdrop__layer nfx-backdrop__layer--violet" />
      <div className="nfx-backdrop__layer nfx-backdrop__layer--amber" />
      <div className="nfx-backdrop__grid" />
    </div>
  );
}