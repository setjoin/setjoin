// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license in GO-LICENSE.
//
// Port of Go 1.26.6 math/exp_amd64.s (the FMA path used by the frozen oracle).
// Keep this explicit evaluation order on every architecture: libm exp differs
// by an ulp and that difference persists in FTRL model bytes. mul_add performs
// the same single IEEE rounding even on hosts without a hardware FMA.
// The underlying Shibata/SLEEF approximation was released to the public domain;
// see Go's source for its provenance. This is arithmetic, not cryptography.
#[allow(clippy::excessive_precision)]
pub(super) fn exp(mut x: f64) -> f64 {
    if x.is_nan() || x == f64::INFINITY {
        return x;
    }
    if x > 7.09782712893384e2 {
        return f64::INFINITY;
    }
    if x < -745.2 {
        return 0.;
    }
    let k = (x * std::f64::consts::LOG2_E).round_ties_even() as i32;
    x = (-(k as f64)).mul_add(0.69314718055966295651160180568695068359375, x);
    x = (-(k as f64)).mul_add(0.28235290563031577122588448175013436025525412068e-12, x);
    x *= 0.0625;
    let mut p: f64 = 2.4801587301587301587e-5;
    for c in [
        1.9841269841269841270e-4,
        1.3888888888888888889e-3,
        8.3333333333333333333e-3,
        4.1666666666666666667e-2,
        1.6666666666666666667e-1,
        0.5,
        1.,
    ] {
        p = p.mul_add(x, c);
    }
    x *= p;
    x *= 2. + x;
    x *= 2. + x;
    x *= 2. + x;
    x = x.mul_add(2. + x, 1.);
    let biased = k + 1023;
    if biased >= 2047 {
        return f64::INFINITY;
    }
    if biased <= 0 {
        if biased < -52 {
            return 0.;
        }
        x *= f64::from_bits(((biased + 1022) as u64) << 52);
        x * f64::from_bits(1u64 << 52)
    } else {
        x * f64::from_bits((biased as u64) << 52)
    }
}
