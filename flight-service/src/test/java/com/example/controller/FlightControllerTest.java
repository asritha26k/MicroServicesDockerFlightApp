package com.example.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.example.model.Airline;
import com.example.model.Flight;
import com.example.request.FlightRequest;
import com.example.request.SearchRequest;
import com.example.service.FlightService;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(FlightController.class)
class FlightControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private FlightService flightService;

	@Autowired
	private ObjectMapper mapper;

	private Flight createFlight() {
		return Flight.builder().flightId(1).airline(Airline.INDIGO).origin("DEL").destination("HYD").price(5000)
				.arrivalTime(LocalDateTime.now().plusDays(2)).departureTime(LocalDateTime.now().plusDays(1)).build();
	}

	private FlightRequest createRequest() {
		return FlightRequest.builder().airline(Airline.INDIGO).origin("DEL").destination("HYD").price(5000)
				.departureTime(LocalDateTime.now().plusDays(1)).arrivalTime(LocalDateTime.now().plusDays(2)).build();
	}

	@Test
	void testRegister() throws Exception {
		FlightRequest req = createRequest();

		when(flightService.registerFlightByIDService(any()))
				.thenReturn(org.springframework.http.ResponseEntity.status(201).body(1));

		mockMvc.perform(post("/flight/register").contentType(MediaType.APPLICATION_JSON)
				.content(mapper.writeValueAsString(req))).andExpect(status().isCreated())
				.andExpect(content().string("1"));
	}

	@Test
	void testGetById() throws Exception {
		Flight flight = createFlight();

		when(flightService.getByIDService(1)).thenReturn(org.springframework.http.ResponseEntity.ok(flight));

		mockMvc.perform(get("/flight/getFlightById/1")).andExpect(status().isOk())
				.andExpect(jsonPath("$.origin").value("DEL"));
	}

	@Test
	void testSearch() throws Exception {
		Flight flight = createFlight();
		SearchRequest req = new SearchRequest("DEL", "HYD");

		when(flightService.getByOriginAndDestinationService(any()))
				.thenReturn(org.springframework.http.ResponseEntity.ok(Arrays.asList(flight)));

		mockMvc.perform(get("/flight/getByOriginDestination").contentType(MediaType.APPLICATION_JSON)
				.content(mapper.writeValueAsString(req))).andExpect(status().isOk())
				.andExpect(jsonPath("$[0].destination").value("HYD"));
	}

	@Test
	void testDelete() throws Exception {
		when(flightService.deleteByIDService(1)).thenReturn(org.springframework.http.ResponseEntity.ok("deleted"));

		mockMvc.perform(delete("/flight/delete/1")).andExpect(status().isOk()).andExpect(content().string("deleted"));
	}

	@Test
	void testRegisterFlightValidationErrors() throws Exception {

		String invalidJson = """
				{
				  "airline": null,
				  "origin": null,
				  "destination": null,
				  "price": -100,
				  "departureTime": null,
				  "arrivalTime": null
				}
				""";

		mockMvc.perform(post("/flight/register").contentType(MediaType.APPLICATION_JSON).content(invalidJson))
				.andExpect(status().isBadRequest()).andExpect(jsonPath("$.message").value("Validation failed"))
				.andExpect(jsonPath("$.errors").exists()).andExpect(jsonPath("$.errors").isString());
	}

	@Test
	void testGetFlightById_ResourceNotFound() throws Exception {

		when(flightService.getByIDService(999))
				.thenThrow(new com.example.exception.ResourceNotFoundException("Flight not found"));

		mockMvc.perform(get("/flight/getFlightById/999")).andExpect(status().isNotFound())
				.andExpect(jsonPath("$.message").value("Flight not found"));
	}

}
