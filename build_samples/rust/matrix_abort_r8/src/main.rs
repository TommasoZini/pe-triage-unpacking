// matrix_abort_r8 - Rust build variant: panic = "abort" (release profile).
type Mat = [[i64; 3]; 3];

fn mul(a: &Mat, b: &Mat) -> Mat {
    let mut c = [[0i64; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            for k in 0..3 {
                c[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    c
}

fn main() {
    let a: Mat = [[1, 2, 3], [4, 5, 6], [7, 8, 9]];
    let ident: Mat = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
    let sq = mul(&a, &a);
    let same = mul(&a, &ident);
    println!("A^2 =");
    for row in &sq {
        println!("  {row:?}");
    }
    let trace: i64 = (0..3).map(|i| sq[i][i]).sum();
    println!("trace(A^2) = {trace}");
    println!("A*I == A : {}", same == a);
}
