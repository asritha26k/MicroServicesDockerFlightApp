package com.example.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

class KafkaProducerConfigTest {

	@Test
	void kafkaProducerConfigLoadsAndHasExpectedProperties() throws Exception {
		AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
		ctx.register(KafkaProducerConfig.class);
		ctx.refresh();

		KafkaTemplate<?, ?> kafkaTemplate = ctx.getBean(KafkaTemplate.class);
		assertNotNull(kafkaTemplate);

		ProducerFactory<?, ?> producerFactory = ctx.getBean(ProducerFactory.class);
		assertNotNull(producerFactory);
		assertTrue(producerFactory instanceof DefaultKafkaProducerFactory);

		DefaultKafkaProducerFactory<?, ?> df = (DefaultKafkaProducerFactory<?, ?>) producerFactory;

		Field configsField;
		Map<?, ?> configs;
		try {
			configsField = DefaultKafkaProducerFactory.class.getDeclaredField("configs");
			configsField.setAccessible(true);
			configs = (Map<?, ?>) configsField.get(df);
		} catch (NoSuchFieldException e) {
			configsField = DefaultKafkaProducerFactory.class.getDeclaredField("configurationProperties");
			configsField.setAccessible(true);
			configs = (Map<?, ?>) configsField.get(df);
		}

		assertNotNull(configs);
		assertEquals("localhost:9092", configs.get(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG));
		assertEquals(StringSerializer.class, configs.get(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG));
		assertEquals(StringSerializer.class, configs.get(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG));

		ctx.close();
	}
}
