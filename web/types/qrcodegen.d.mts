// The part of the vendored QR code generator (vendor/qrcodegen/qrcodegen.mjs, Project
// Nayuki, MIT) that src/qr.mjs uses. The build copies this file next to the vendored
// module as js/vendor/qrcodegen/qrcodegen.d.mts, so the type check reads these
// declarations instead of checking the third-party file.
declare namespace qrcodegen {
  namespace QrCode {
    class Ecc {
      static readonly LOW: Ecc;
      static readonly MEDIUM: Ecc;
      static readonly QUARTILE: Ecc;
      static readonly HIGH: Ecc;
      readonly ordinal: number;
    }
  }
  class QrCode {
    static encodeBinary(data: Iterable<number>, ecl: QrCode.Ecc): QrCode;
    readonly version: number;
    readonly size: number;
    readonly errorCorrectionLevel: QrCode.Ecc;
    readonly mask: number;
    getModule(x: number, y: number): boolean;
  }
}
export default qrcodegen;
