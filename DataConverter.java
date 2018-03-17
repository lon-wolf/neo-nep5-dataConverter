
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;

import com.exceptions.GenericServiceException;

public class DataConverter {
	public static void main(String[] args) throws UnsupportedEncodingException, GenericServiceException {
		System.out.println(hashToAddress("a0d2f277fdb6d5bafe4e42009113d21c840827ba"));

		System.out.println(toAddressHash("AWSEU4BXpjGVdw9ajnFBXh8Rg8cgw9f3Zo"));

		System.out.println(toAmount("0000bc93e9fe2461"));

		System.out.println(toEventString("5445535432"));

	}

	public static byte[] reverse(byte[] arr) {
		for (int i = 0; i < arr.length / 2; i++) {
			byte temp = arr[i];
			arr[i] = arr[arr.length - 1 - i];
			arr[arr.length - 1 - i] = temp;
		}
		return arr;

	}

	public static String hashToAddress(String hash) {
		String str1 = "a0d2f277fdb6d5bafe4e42009113d21c840827ba";
		byte[] array = DatatypeConverter.parseHexBinary(str1);
		/*
		 * Note that for the hexadecimal string with "0x" prefix, it is processed as big
		 * endian; otherwise, it is processed as small endian. if 0x then don;t reverse
		 */
		array = reverse(array);
		String s = new String(DatatypeConverter.printHexBinary(array));
		UInt160 uint160 = UInt160.parse(s);
		return Base58.encodeChecked(23, uint160.data_bytes);
	}

	public static String toAddressHash(String address) throws GenericServiceException {
		byte[] data = Base58.decodeChecked(address);
		byte[] arr = new byte[data.length - 1];
		System.arraycopy(data, 1, arr, 0, arr.length);
		arr = reverse(arr);
		return "0x" + (new String(DatatypeConverter.printHexBinary(arr)).toLowerCase());
	}

	public static String toAmount(String hash) {
		byte[] array = DatatypeConverter.parseHexBinary(hash);
		array = reverse(array);
		BigInteger biResult = new BigInteger(array);
		return biResult.toString();
	}

	public static String toEventString(String str) {
		return new String(DatatypeConverter.parseHexBinary(str));
	}

	public static String encodeEventString(String str) {
		return new String(DatatypeConverter.printHexBinary(str.getBytes()));
	}
}
