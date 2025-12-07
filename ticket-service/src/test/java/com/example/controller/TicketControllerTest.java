package com.example.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.example.exception.ResourceNotFoundException;
import com.example.request.BookTicketRequest;
import com.example.response.TicketResponse;
import com.example.service.TicketService;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(controllers = TicketController.class, excludeAutoConfiguration = {
		org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
		org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class })
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = "spring.cloud.config.enabled=false")
class TicketControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private TicketService ticketService;

	@Autowired
	private ObjectMapper mapper;

	@Test
	void testBookTicket() throws Exception {

		BookTicketRequest req = new BookTicketRequest();
		req.setFlightId(1);
		req.setPassengerId(10);
		req.setSeatNo("A1");

		when(ticketService.bookTicketService(any())).thenReturn(ResponseEntity.ok("PNR12345"));

		mockMvc.perform(MockMvcRequestBuilders.post("/ticket/book").contentType(MediaType.APPLICATION_JSON)
				.content(mapper.writeValueAsString(req))).andExpect(status().isOk())
				.andExpect(content().string("PNR12345"));
	}

	@Test
	void testGetByPnr() throws Exception {

		TicketResponse resp = new TicketResponse();
		resp.setPnr("ABCD1234");
		resp.setName("John");

		when(ticketService.getByPnrService("ABCD1234")).thenReturn(ResponseEntity.ok(resp));

		mockMvc.perform(MockMvcRequestBuilders.get("/ticket/getByPnr/ABCD1234")).andExpect(status().isOk())
				.andExpect(jsonPath("$.pnr").value("ABCD1234")).andExpect(jsonPath("$.name").value("John"));
	}

	@Test
	void testGetTicketsByEmail() throws Exception {

		TicketResponse t1 = new TicketResponse();
		t1.setPnr("A1");

		TicketResponse t2 = new TicketResponse();
		t2.setPnr("A2");

		when(ticketService.getTicketsByEmailService("x@gmail.com"))
				.thenReturn(ResponseEntity.ok(Arrays.asList(t1, t2)));

		mockMvc.perform(MockMvcRequestBuilders.get("/ticket/getTicketsByEmail/x@gmail.com")).andExpect(status().isOk())
				.andExpect(jsonPath("$.length()").value(2)).andExpect(jsonPath("$[0].pnr").value("A1"));
	}

	@Test
	void testBookTicket_ValidationError() throws Exception {

		BookTicketRequest req = new BookTicketRequest();

		mockMvc.perform(MockMvcRequestBuilders.post("/ticket/book").contentType(MediaType.APPLICATION_JSON)
				.content(mapper.writeValueAsString(req))).andExpect(status().isBadRequest())
				.andExpect(status().isBadRequest()).andExpect(jsonPath("$.message").value("Validation failed"))
				.andExpect(jsonPath("$.errors").exists()).andExpect(jsonPath("$.errors").isString());
	}

	@Test
	void testGetByPnr_NotFound() throws Exception {

		when(ticketService.getByPnrService("INVALID")).thenThrow(new ResourceNotFoundException("Ticket not found"));

		mockMvc.perform(MockMvcRequestBuilders.get("/ticket/getByPnr/INVALID")).andExpect(status().isNotFound())
				.andExpect(jsonPath("$.message").value("Ticket not found"));
	}

}
