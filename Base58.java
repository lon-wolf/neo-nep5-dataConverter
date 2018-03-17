import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import com.exceptions.GenericServiceException;

public class Base58 {
	public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
	private static final char ENCODED_ZERO = ALPHABET[0];
	private static final int[] INDEXES = new int[128];
	static {
		Arrays.fill(INDEXES, -1);
		for (int i = 0; i < ALPHABET.length; i++) {
			INDEXES[ALPHABET[i]] = i;
		}
	}

	/**
	 * Encodes the given bytes as a base58 string (no checksum is appended).
	 *
	 * @param input
	 *            the bytes to encode
	 * @return the base58-encoded string
	 */
	public static String encode(byte[] input) {
		if (input.length == 0) {
			return "";
		}
		// Count leading zeros.
		int zeros = 0;
		while (zeros < input.length && input[zeros] == 0) {
			++zeros;
		}
		// Convert base-256 digits to base-58 digits (plus conversion to ASCII
		// characters)
		input = Arrays.copyOf(input, input.length); // since we modify it in-place
		char[] encoded = new char[input.length * 2]; // upper bound
		int outputStart = encoded.length;
		for (int inputStart = zeros; inputStart < input.length;) {
			encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
			if (input[inputStart] == 0) {
				++inputStart; // optimization - skip leading zeros
			}
		}
		// Preserve exactly as many leading encoded zeros in output as there were
		// leading zeros in input.
		while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
			++outputStart;
		}
		while (--zeros >= 0) {
			encoded[--outputStart] = ENCODED_ZERO;
		}
		// Return encoded string (including encoded leading zeros).
		return new String(encoded, outputStart, encoded.length - outputStart);
	}

	/**
	 * Encodes the given version and bytes as a base58 string. A checksum is
	 * appended.
	 * 
	 * @param version
	 *            the version to encode
	 * @param payload
	 *            the bytes to encode, e.g. pubkey hash
	 * @return the base58-encoded string
	 */
	public static String encodeChecked(int version, byte[] payload) {
		if (version < 0 || version > 255)
			throw new IllegalArgumentException("Version not in range.");

		// A stringified buffer is:
		// 1 byte version + data bytes + 4 bytes check code (a truncated hash)
		byte[] addressBytes = new byte[1 + payload.length + 4];
		addressBytes[0] = (byte) version;
		System.arraycopy(payload, 0, addressBytes, 1, payload.length);
		byte[] checksum = hashTwice(addressBytes, 0, payload.length + 1);
		System.arraycopy(checksum, 0, addressBytes, payload.length + 1, 4);
		return Base58.encode(addressBytes);
	}

	private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
		// this is just long division which accounts for the base of the input digits
		int remainder = 0;
		for (int i = firstDigit; i < number.length; i++) {
			int digit = (int) number[i] & 0xFF;
			int temp = remainder * base + digit;
			number[i] = (byte) (temp / divisor);
			remainder = temp % divisor;
		}
		return (byte) remainder;
	}

	public static byte[] hashTwice(byte[] input, int offset, int length) {
		MessageDigest digest = newDigest();
		digest.update(input, offset, length);
		return digest.digest(digest.digest());
	}

	public static MessageDigest newDigest() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // Can't happen.
		}
	}

	public static byte[] decodeChecked(String input) throws GenericServiceException {
		byte[] decoded = decode(input);
		if (decoded.length < 4)
			throw new GenericServiceException("Input too short: " + decoded.length);
		byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
		byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
		byte[] actualChecksum = Arrays.copyOfRange(hashTwice(data, 0, data.length), 0, 4);
		if (!Arrays.equals(checksum, actualChecksum))
			throw new GenericServiceException("Invalid checksum");
		return data;
	}

	public static byte[] decode(String input) throws GenericServiceException {
		if (input.length() == 0) {
			return new byte[0];
		}
		// Convert the base58-encoded ASCII chars to a base58 byte sequence (base58
		// digits).
		byte[] input58 = new byte[input.length()];
		for (int i = 0; i < input.length(); ++i) {
			char c = input.charAt(i);
			int digit = c < 128 ? INDEXES[c] : -1;
			if (digit < 0) {
				throw new GenericServiceException("Invalide address");
			}
			input58[i] = (byte) digit;
		}
		// Count leading zeros.
		int zeros = 0;
		while (zeros < input58.length && input58[zeros] == 0) {
			++zeros;
		}
		// Convert base-58 digits to base-256 digits.
		byte[] decoded = new byte[input.length()];
		int outputStart = decoded.length;
		for (int inputStart = zeros; inputStart < input58.length;) {
			decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
			if (input58[inputStart] == 0) {
				++inputStart; // optimization - skip leading zeros
			}
		}
		// Ignore extra leading zeroes that were added during the calculation.
		while (outputStart < decoded.length && decoded[outputStart] == 0) {
			++outputStart;
		}
		// Return decoded data (including original number of leading zeros).
		return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
	}
}
