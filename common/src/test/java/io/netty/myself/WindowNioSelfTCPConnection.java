package io.netty.myself;

import java.nio.channels.Selector;
import java.lang.RuntimeException;
import java.lang.Thread;
/**
 * 验证：http://haoel.blog.51cto.com/313033/124582/
 */
public class WindowNioSelfTCPConnection {
	private static final int MAXSIZE = 65535;

	public static final void main(String argc[]) {
		Selector[] sels = new Selector[MAXSIZE];
		try {
			for (int i = 0; i < MAXSIZE; ++i) {
				System.out.println(i);
				sels[i] = Selector.open();
				// sels[i].close();
			}
			Thread.sleep(300000);
		} catch (Exception ex) {
			System.out.println(ex);
			throw new RuntimeException(ex);
		}
	}
}
//java.io.IOException: Unable to establish loopback connection
//Exception in thread "main" java.lang.RuntimeException: java.io.IOException: Unable to establish loopback connection
//	at io.netty.myself.WindowNioSelfTCPConnection.main(WindowNioSelfTCPConnection.java:21)
//Caused by: java.io.IOException: Unable to establish loopback connection
//	at sun.nio.ch.PipeImpl$Initializer.run(Unknown Source)
//	at sun.nio.ch.PipeImpl$Initializer.run(Unknown Source)
//	at java.security.AccessController.doPrivileged(Native Method)
//	at sun.nio.ch.PipeImpl.<init>(Unknown Source)
//	at sun.nio.ch.SelectorProviderImpl.openPipe(Unknown Source)
//	at java.nio.channels.Pipe.open(Unknown Source)
//	at sun.nio.ch.WindowsSelectorImpl.<init>(Unknown Source)
//	at sun.nio.ch.WindowsSelectorProvider.openSelector(Unknown Source)
//	at java.nio.channels.Selector.open(Unknown Source)
//	at io.netty.myself.WindowNioSelfTCPConnection.main(WindowNioSelfTCPConnection.java:15)
//Caused by: java.net.SocketException: No buffer space available (maximum connections reached?): connect
//	at sun.nio.ch.Net.connect0(Native Method)
//	at sun.nio.ch.Net.connect(Unknown Source)
//	at sun.nio.ch.Net.connect(Unknown Source)
//	at sun.nio.ch.SocketChannelImpl.connect(Unknown Source)
//	at java.nio.channels.SocketChannel.open(Unknown Source)
//	... 10 more