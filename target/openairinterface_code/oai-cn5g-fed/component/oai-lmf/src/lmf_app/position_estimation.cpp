/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "position_estimation.hpp"
#include <cmath>
#include <cstdio>
#include <cblas.h>
#include <lapacke.h>
#include <cstring>

int inverse_matrix(double A[2][2], double A_inv[2][2]) {
  constexpr int n   = 2;
  constexpr int lda = n;

  std::memcpy(A_inv, A, sizeof(double) * n * n);

  int ipiv[2];
  int info = LAPACKE_dgetrf(LAPACK_ROW_MAJOR, n, n, &A_inv[0][0], lda, ipiv);
  if (info != 0) {
    std::printf("Matrix inversion failed: dgetrf info=%d\n", info);
    return -1;
  }

  info = LAPACKE_dgetri(LAPACK_ROW_MAJOR, n, &A_inv[0][0], lda, ipiv);
  if (info != 0) {
    std::printf("Matrix inversion failed: dgetri info=%d\n", info);
    return -1;
  }

  return 0;
}

// Function to perform LLS estimation
void lls_estimation(
    double trp_pos[][3], int trp_pos_size, double dd_estimated[],
    int dd_estimated_size, double pos_est[2]) {
  double A[trp_pos_size - 1][2];
  double b[trp_pos_size - 1];

  for (int i = 1; i < trp_pos_size; i++) {
    A[i - 1][0] = 2 * (trp_pos[i][0] - trp_pos[0][0]);
    A[i - 1][1] = 2 * (trp_pos[i][1] - trp_pos[0][1]);
    b[i - 1]    = pow(trp_pos[i][0], 2) - pow(trp_pos[0][0], 2) +
               pow(trp_pos[i][1], 2) - pow(trp_pos[0][1], 2) -
               pow(dd_estimated[i - 1], 2);
  }

  double AtA[2][2] = {{0.0, 0.0}, {0.0, 0.0}};
  double Atb[2]    = {0.0, 0.0};

  for (int i = 0; i < trp_pos_size - 1; i++) {
    AtA[0][0] += A[i][0] * A[i][0];
    AtA[0][1] += A[i][0] * A[i][1];
    AtA[1][0] += A[i][1] * A[i][0];
    AtA[1][1] += A[i][1] * A[i][1];
    Atb[0] += A[i][0] * b[i];
    Atb[1] += A[i][1] * b[i];
  }

  double AtA_inv[2][2];
  if (inverse_matrix(AtA, AtA_inv) != 0) {
    printf("LLS matrix inversion failed.\n");
    return;
  }

  pos_est[0] = AtA_inv[0][0] * Atb[0] + AtA_inv[0][1] * Atb[1];
  pos_est[1] = AtA_inv[1][0] * Atb[0] + AtA_inv[1][1] * Atb[1];

  pos_est[0] /= 2.0;
  pos_est[1] /= 2.0;

  pos_est[0] += trp_pos[0][0];
  pos_est[1] += trp_pos[0][1];
}
