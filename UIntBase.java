import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public abstract class UIntBase implements Serializable {
	protected byte[] data_bytes;

	protected UIntBase(int bytes, byte[] value) {
		if (value == null) {
			this.data_bytes = new byte[bytes];
			return;
		}
		if (value.length != bytes) {
			throw new IllegalArgumentException();
		}
		this.data_bytes = value;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof UIntBase)) {
			return false;
		}
		UIntBase other = (UIntBase) obj;
		return Arrays.equals(this.data_bytes, other.data_bytes);
	}

	@Override
	public int hashCode() {
		return ByteBuffer.wrap(data_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
	}

	public byte[] toArray() {
		return data_bytes;
	}

	/**
	 * 转为16进制字符串
	 * 
	 * @return 返回16进制字符串
	 */
	@Override
	public String toString() {
		return Helper.toHexString(Helper.reverse(data_bytes));
	}

}
