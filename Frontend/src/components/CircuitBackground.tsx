import React from 'react';
export function CircuitBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Real circuit board background image */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
          'url(https://cdn.magicpatterns.com/uploads/5e9xJYyhk3xe2Re3JLnEcY/background.png)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat'
        }} />


      {/* Circuit trace overlay - multiply blend to show traces on dark bg */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
          'url(https://cdn.magicpatterns.com/uploads/nYboC99AseE7DLWYxi98in/overlay.png)',
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
          'url(https://cdn.magicpatterns.com/uploads/cFBNZVXVY45Pzsi7xVBa6j/cables.png)',
          backgroundSize: 'contain',
          backgroundPosition: 'bottom left',
          backgroundRepeat: 'no-repeat',
          mixBlendMode: 'screen',
          opacity: 0.7
        }} />

    </div>);

}