package com.aes;

import java.util.Arrays;

public class AES128 {
    private static final int Nb = 4; // Número de colunas (32 bits cada) no estado
    private static final int Nk = 4; // Número de colunas na chave
    private static final int Nr = 10; // Número de rodadas para AES-128

    private byte[] key;
    private byte[][] state;

    public AES128(byte[] key) {
        if (key.length != 16) {
            throw new IllegalArgumentException("Chave deve ter 128 bits (16 bytes)");
        }
        this.key = key;
        this.state = new byte[4][Nb];
    }

    // Criptografa o texto claro
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext.length % 16 != 0) {
            plaintext = pad(plaintext);
        }

        for (int i = 0; i < 16; i++) {
            state[i / 4][i % 4] = plaintext[i];
        }

        byte[][] expandedKeys = keyExpansion(key);

        addRoundKey(state, Arrays.copyOfRange(expandedKeys, 0, 4));

        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKeys, round * 4, (round + 1) * 4));
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(expandedKeys, Nr * 4, (Nr + 1) * 4));

        byte[] ciphertext = new byte[16];
        for (int i = 0; i < 16; i++) {
            ciphertext[i] = state[i / 4][i % 4];
        }

        return ciphertext;
    }

    // Descriptografa o texto cifrado
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext.length % 16 != 0) {
            throw new IllegalArgumentException("O bloco de entrada deve ter 128 bits (16 bytes)");
        }

        for (int i = 0; i < 16; i++) {
            state[i / 4][i % 4] = ciphertext[i];
        }

        byte[][] expandedKeys = keyExpansion(key);

        addRoundKey(state, Arrays.copyOfRange(expandedKeys, Nr * 4, (Nr + 1) * 4));

        for (int round = Nr - 1; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKeys, round * 4, (round + 1) * 4));
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, Arrays.copyOfRange(expandedKeys, 0, 4));

        byte[] plaintext = new byte[16];
        for (int i = 0; i < 16; i++) {
            plaintext[i] = state[i / 4][i % 4];
        }

        return removePadding(plaintext);
    }

    private byte[][] keyExpansion(byte[] key) {
        byte[][] expandedKeys = new byte[4 * (Nr + 1)][4];
        byte[] temp = new byte[4];
        int i = 0;

        while (i < Nk) {
            expandedKeys[i][0] = key[4 * i];
            expandedKeys[i][1] = key[4 * i + 1];
            expandedKeys[i][2] = key[4 * i + 2];
            expandedKeys[i][3] = key[4 * i + 3];
            i++;
        }

        i = Nk;
        while (i < 4 * (Nr + 1)) {
            temp[0] = expandedKeys[i - 1][0];
            temp[1] = expandedKeys[i - 1][1];
            temp[2] = expandedKeys[i - 1][2];
            temp[3] = expandedKeys[i - 1][3];

            if (i % Nk == 0) {
                temp = xorWords(rotateWord(temp), subWord(temp));
                temp[0] = (byte) (temp[0] ^ rCon(i / Nk));

            }

            expandedKeys[i] = xorWords(expandedKeys[i - Nk], temp);
            i++;
        }

        return expandedKeys;
    }

    private byte[] xorWords(byte[] word1, byte[] word2) {
        byte[] result = new byte[word1.length];
        for (int i = 0; i < word1.length; i++) {
            result[i] = (byte) (word1[i] ^ word2[i]);
        }
        return result;
    }

    private void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = sBoxTransform(state[i][j]);
            }
        }
    }

    // Desfaz a operação SubBytes
    private void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = invSBoxTransform(state[i][j]);
            }
        }
    }

    // Realiza a operação ShiftRows
    private void shiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            state[i] = leftRotate(state[i], i);
        }
    }

    // Desfaz a operação ShiftRows
    private void invShiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            state[i] = rightRotate(state[i], i);
        }
    }

    // Realiza a operação MixColumns
    private void mixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte[] col = new byte[4];
            for (int i = 0; i < 4; i++) {
                col[i] = state[i][c];
            }

            state[0][c] = (byte) (gfMultiply(col[0], (byte) 0x02) ^ gfMultiply(col[1], (byte) 0x03)
                    ^ col[2] ^ col[3]);
            state[1][c] = (byte) (col[0] ^ gfMultiply(col[1], (byte) 0x02)
                    ^ gfMultiply(col[2], (byte) 0x03) ^ col[3]);
            state[2][c] = (byte) (col[0] ^ col[1] ^ gfMultiply(col[2], (byte) 0x02)
                    ^ gfMultiply(col[3], (byte) 0x03));
            state[3][c] = (byte) (gfMultiply(col[0], (byte) 0x03) ^ col[1] ^ col[2]
                    ^ gfMultiply(col[3], (byte) 0x02));
        }
    }

    // Desfaz a operação MixColumns
    private void invMixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte[] col = new byte[4];
            for (int i = 0; i < 4; i++) {
                col[i] = state[i][c];
            }

            state[0][c] = (byte) (gfMultiply(col[0], (byte) 0x0e) ^ gfMultiply(col[1], (byte) 0x0b)
                    ^ gfMultiply(col[2], (byte) 0x0d) ^ gfMultiply(col[3], (byte) 0x09));
            state[1][c] = (byte) (gfMultiply(col[0], (byte) 0x09) ^ gfMultiply(col[1], (byte) 0x0e)
                    ^ gfMultiply(col[2], (byte) 0x0b) ^ gfMultiply(col[3], (byte) 0x0d));
            state[2][c] = (byte) (gfMultiply(col[0], (byte) 0x0d) ^ gfMultiply(col[1], (byte) 0x09)
                    ^ gfMultiply(col[2], (byte) 0x0e) ^ gfMultiply(col[3], (byte) 0x0b));
            state[3][c] = (byte) (gfMultiply(col[0], (byte) 0x0b) ^ gfMultiply(col[1], (byte) 0x0d)
                    ^ gfMultiply(col[2], (byte) 0x09) ^ gfMultiply(col[3], (byte) 0x0e));
        }
    }

    byte[] pad(byte[] data) {
        int paddingLength = 16 - (data.length % 16);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);

        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) paddingLength;
        }

        return paddedData;
    }

    private byte[] unpad(byte[] data) {
        int paddingLength = data[data.length - 1];
        byte[] unpaddedData = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }

    private byte[] rightRotate(byte[] row, int n) {
        byte[] newRow = new byte[row.length];
        for (int i = 0; i < row.length; i++) {
            newRow[i] = row[(i - n + row.length) % row.length];
        }
        return newRow;
    }

    private byte invSBoxTransform(byte in) {
        byte[] invSBox = {
                (byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38,
                (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb,
                (byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87,
                (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb,
                (byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d,
                (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e,
                (byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2,
                (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25,
                (byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16,
                (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92,
                (byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda,
                (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
                (byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a,
                (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06,
                (byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02,
                (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b,
                (byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea,
                (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73,
                (byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85,
                (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e,
                (byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89,
                (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b,
                (byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20,
                (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4,
                (byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31,
                (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f,
                (byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d,
                (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef,
                (byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0,
                (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
                (byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26,
                (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d
        };
        return invSBox[in & 0xFF];
    }

    private byte[] leftRotate(byte[] row, int n) {
        byte[] newRow = new byte[row.length];
        for (int i = 0; i < row.length; i++) {
            newRow[i] = row[(i + n) % row.length];
        }
        return newRow;
    }

    private byte gfMultiply(byte a, byte b) {
        byte result = 0;
        byte highBitMask = (byte) 0x80;
        byte highBit = 0;
        byte modulo = (byte) 0x1b;

        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            highBit = (byte) (a & highBitMask);
            a <<= 1;
            if (highBit != 0) {
                a ^= modulo;
            }
            b >>= 1;
        }
        return result;
    }

    private void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] ^= roundKey[i][j];
            }
        }
    }

    private byte[] rotateWord(byte[] word) {
        byte temp = word[0];
        for (int i = 0; i < 3; i++) {
            word[i] = word[i + 1];
        }
        word[3] = temp;
        return word;
    }

    private byte[] subWord(byte[] word) {
        for (int i = 0; i < 4; i++) {
            word[i] = sBoxTransform(word[i]);
        }
        return word;
    }

    private byte rCon(int round) {
        byte[] rCon = {
                (byte) 0x8d, (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08,
                (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1b, (byte) 0x36
        };
        return rCon[round];
    }

    private static final byte[] sBox = {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0,
            (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc,
            (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a,
            (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
            (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0,
            (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
            (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b,
            (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
            (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85,
            (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
            (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5,
            (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
            (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17,
            (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
            (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88,
            (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
            (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c,
            (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
            (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9,
            (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
            (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6,
            (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
            (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e,
            (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
            (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
            (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
            (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68,
            (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16
    };

    private byte sBoxTransform(byte in) {
        return sBox[in & 0xFF];
    }

    public byte[] addPadding(byte[] data) {
        int paddingLength = 16 - (data.length % 16);
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
        Arrays.fill(paddedData, data.length, paddedData.length, (byte) paddingLength);
        return paddedData;
    }

    public byte[] removePadding(byte[] data) {
        int paddingLength = data[data.length - 1];
        if (paddingLength > data.length) {
            throw new IllegalArgumentException("Padding length is greater than data length.");
        }
        return Arrays.copyOf(data, data.length - paddingLength);
    }

}
