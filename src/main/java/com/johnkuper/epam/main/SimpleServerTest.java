package com.johnkuper.epam.main;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

@SuppressWarnings("restriction")
public class SimpleServerTest {

	static class RequestHandler implements HttpHandler {
		public void handle(HttpExchange t) throws IOException {

			IOException e = null;
			OutputStream os = null;
			try {

				String response = "This is the response";
				t.sendResponseHeaders(200, response.length());
				os = t.getResponseBody();
				os.write(response.getBytes());

			} catch (IOException ex) {
				e = ex;
				throw ex;
			} finally {
				try {
					if (os != null)
						os.close();
				} catch (IOException ex) {
					if (e != null)
						throw ex;
					else
						throw e;
				}
			}
		}
	}

	@Test
	public void testSimpleServer() throws IOException, InterruptedException {

		HttpServer server = HttpServer.create(new InetSocketAddress(8000), 5);

		server.createContext("/applications/myapp", new RequestHandler());

		ExecutorService executor = Executors.newFixedThreadPool(5);
		server.setExecutor(executor); // creates a default executor
		server.start();
		executor.awaitTermination(Integer.MAX_VALUE, TimeUnit.DAYS);
	}
}
