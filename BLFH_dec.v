`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 25.04.2024 14:02:09
// Design Name: 
// Module Name: BLFH_dec
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module blowfish_decrypt (
  input [31:0] key,          // Input secret key (32 bits)
  input [63:0] dec_ciphertext, // Input data to be decrypted (64 bits)
  output reg [63:0] decryptedtext // Decrypted output data (64 bits)
);

  // P-array to store pre-processing key data (18 x 32 bits)
  reg [31:0] P[17:0];

  // Temporary variables to hold left and right halves of data (32 bits each)
  reg [31:0] L, R;

  reg [7:0] b0, b1, b2, b3;
  integer i, b0_dec, b1_dec, b2_dec, b3_dec;
  reg [31:0] sb0,sb1,sb2,sb3,res;

  // S-boxes to store pre-computed values for non-linear mixing (4 x 256 x 32 bits)
  reg [31:0] S0 [255:0];
  reg [31:0] S1 [255:0];
  reg [31:0] S2 [255:0];
  reg [31:0] S3 [255:0];

  // Initializing P-array with pre-defined constant values during startup
  initial begin
    P[0]  = 32'h243f6a88;
    P[1]  = 32'h85a308d3;
    P[2]  = 32'h13198a2e;
    P[3]  = 32'h03707344;
    P[4]  = 32'ha4093822;
    P[5]  = 32'h299f31d0;
    P[6]  = 32'h082efa98;
    P[7]  = 32'hec4e6c89;
    P[8]  = 32'h452821e6;
    P[9]  = 32'h38d01377;
    P[10] = 32'hbe5466cf;
    P[11] = 32'h34e90c6c;
    P[12] = 32'hc0ac29b7;
    P[13] = 32'hc97c50dd;
    P[14] = 32'h3f84d5b5;
    P[15] = 32'hb5470917;
    P[16] = 32'h9216d5d9;
    P[17] = 32'h8979fb1b;
  end

  // Reading pre-computed S-box values from external text files during startup
  initial begin
    $readmemh("sbox1.txt", S0);
    $readmemh("sbox2.txt", S1);
    $readmemh("sbox3.txt", S2);
    $readmemh("sbox4.txt", S3);
  end

  // Main decryption loop with 16 rounds (order reversed compared to encryption)
  always @(dec_ciphertext) begin
    // Xor each element in P-array with the key for enhanced security (same as encryption)
    for (i = 0; i < 18; i = i + 1) begin
      P[i] = P[i] ^ key;
    end

    // Splitting ciphertext into left and right halves
    L = dec_ciphertext[63:32];
    R = dec_ciphertext[31:0];

    // Perform 16 rounds of decryption (order reversed compared to encryption)
    for (i = 17; i > 1; i = i - 1) begin  // Decryption starts from the last round (i = 17)
      // Xor left half with current subkey from P-array (order reversed compared to encryption)
      L = L ^ P[i];

      // Splitting left half (L) into individual bytes for S-box lookup
      b0 = L[31:24];
      b1 = L[23:16];
      b2 = L[15:8];
      b3 = L[7:0];

      // Convert bytes to unsigned integers for S-box indexing
      b0_dec = $unsigned(b0);
      b1_dec = $unsigned(b1);
      b2_dec = $unsigned(b2);
      b3_dec = $unsigned(b3);

      // Lookup pre-computed S-box values based on individual bytes
      sb0 = S0[b0_dec];
      sb1 = S1[b1_dec];
      sb2 = S2[b2_dec];
      sb3 = S3[b3_dec];

      // Perform non-linear mixing with S-box outputs
      res = sb0 ^ sb1 ^ sb2 ^ sb3;

      // Xor right half with the result for confusion (order reversed compared to encryption)
      R = R ^ res;

      // Swap left and right halves for Feistel network (rounds 14 to 2)
      {L, R} = {R, L};
    end

    // Swap left and right halves back after the final round (no further swapping needed)
    {L, R} = {R, L};

    // Xor each half with final subkeys from P-array (order reversed compared to encryption)
    L = L ^ P[0];
    R = R ^ P[1];

    // Combine left and right halves to form the final decrypted text
    decryptedtext = {L, R};

    // Display the decrypted data for debugging purposes (can be removed)
    $display("decryptedtext:%h", decryptedtext);
  end
endmodule