package com.example.demo.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaTopicConfig {

	@Value("${kafka.topic.ticket-booked}")
	private String ticketBookedTopic;

	@Bean
	public NewTopic createTicketBookedTopic() {
		return TopicBuilder.name(ticketBookedTopic).partitions(1).replicas(1).build();
	}
}
