/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * Lightweight test server backed by [HttpServer]. Requests are recorded so
 * tests can assert headers / paths; responses are programmable per-request.
 */
class LocalHttpServer {

    data class Response(val status: Int, val body: String, val headers: Map<String, String> = emptyMap())

    data class RecordedRequest(
        val method: String,
        val path: String,
        val headers: Map<String, List<String>>,
        val body: String,
    )

    private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    private val responses: ConcurrentLinkedQueue<Response> = ConcurrentLinkedQueue()
    private val recorded: ConcurrentLinkedQueue<RecordedRequest> = ConcurrentLinkedQueue()
    private val hits = AtomicInteger(0)

    fun start() {
        server.createContext("/", HttpHandler { exchange -> handle(exchange) })
        server.start()
    }

    fun stop() {
        server.stop(0)
    }

    fun baseUrl(): String = "http://127.0.0.1:${server.address.port}"

    fun enqueue(response: Response) {
        responses.add(response)
    }

    fun requestCount(): Int = hits.get()
    fun recorded(): List<RecordedRequest> = recorded.toList()

    private fun handle(exchange: HttpExchange) {
        hits.incrementAndGet()
        val bodyBytes = exchange.requestBody.readAllBytes()
        recorded.add(
            RecordedRequest(
                method = exchange.requestMethod,
                path = exchange.requestURI.toString(),
                headers = exchange.requestHeaders.toMap(),
                body = String(bodyBytes, StandardCharsets.UTF_8),
            )
        )
        val response = responses.poll() ?: Response(500, "no queued response")
        response.headers.forEach { (k, v) -> exchange.responseHeaders.add(k, v) }
        val payload = response.body.toByteArray(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(response.status, payload.size.toLong())
        exchange.responseBody.use { it.write(payload) }
    }
}
