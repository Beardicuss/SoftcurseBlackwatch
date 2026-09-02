export function CircuitBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Real circuit board background image */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
          'url(./background.png)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat'
        }} />


      {/* Circuit trace overlay - multiply blend to show traces on dark bg */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
          'url(./overlay.png)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          mixBlendMode: 'screen',
          opacity: 0.4
        }} />


      {/* Cables image - bottom area */}
      <div
        className="absolute bottom-0 left-0 right-0"
        style={{
          height: '45%',
          backgroundImage:
          'url(./cables.png)',
          backgroundSize: 'contain',
          backgroundPosition: 'bottom left',
          backgroundRepeat: 'no-repeat',
          mixBlendMode: 'screen',
          opacity: 0.7
        }} />

    </div>);

}
