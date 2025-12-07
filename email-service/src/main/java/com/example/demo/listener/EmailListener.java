package com.example.demo.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Service
public class EmailListener {
	private static final Logger logger = LoggerFactory.getLogger(EmailListener.class);

	@KafkaListener(topics = "${kafka.topic.ticket-booked}", groupId = "${kafka.group.email}")
	public void listen(String message) {
		logger.info("📩 Email-service received: {}", message);

	}
}
