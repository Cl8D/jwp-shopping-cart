package cart.controller;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.responseHeaders;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import cart.controller.dto.ProductDto;
import cart.controller.helper.RestDocsHelper;
import cart.service.ProductService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.restdocs.snippet.Attributes;

@WebMvcTest(AdminRestController.class)
class AdminRestControllerTest extends RestDocsHelper {

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private ProductService productService;

    @DisplayName("상품 정보를 추가한다")
    @Test
    void addProduct() throws Exception {
        // given
        final ProductDto productDto = new ProductDto(1L, "치킨", "chickenUrl", 20000, "KOREAN");
        when(productService.save(any())).thenReturn(1L);

        // when, then
        mockMvc.perform(post("/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(productDto))
                .characterEncoding(StandardCharsets.UTF_8))
            .andExpectAll(
                status().isCreated(),
                header().string("Location", "/1"))
            .andDo(
                documentationResultHandler.document(
                    requestFields(
                        fieldWithPath("id").description("상품 아이디").ignored(),
                        fieldWithPath("name").description("상품 이름")
                            .attributes(new Attributes.Attribute(RANGE, "1-25")),
                        fieldWithPath("imageUrl").description("상품 이미지 URL").optional(),
                        fieldWithPath("price").description("상품 가격")
                            .attributes(new Attributes.Attribute(RANGE, "0-10,000,000")),
                        fieldWithPath("category").description(
                            "상품 카테고리(KOREAN, JAPANESE, CHINESE, WESTERN, SNACK, DESSERT)")),
                    responseHeaders(
                        headerWithName("Location").description("상품 세부 정보 URI")
                    )
                )
            );
    }

    @DisplayName("상품 정보를 추가 시 잘못된 정보 형식으로 들어오면 예외가 발생한다")
    @Test
    void addProduct_fail() throws Exception {
        // given
        final ProductDto productDto = new ProductDto(1L, "", "", null, null);

        // when, then
        mockMvc.perform(post("/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(productDto))
                .characterEncoding(StandardCharsets.UTF_8)
            )
            .andExpectAll(
                status().isBadRequest(),
                jsonPath("$.errorMessage",
                    containsInAnyOrder(
                        "상품 이름은 비어있을 수 없습니다.",
                        "상품 가격은 비어있을 수 없습니다.",
                        "상품 카테고리는 비어있을 수 없습니다.")))
            .andDo(
                documentationResultHandler.document(
                    requestFields(
                        fieldWithPath("id").description("상품 아이디").ignored(),
                        fieldWithPath("name").description("잘못된 상품 이름"),
                        fieldWithPath("imageUrl").description("상품 이미지 URL").optional(),
                        fieldWithPath("price").description("잘못된 상품 가격"),
                        fieldWithPath("category").description("잘못된 상품 카테고리"))
                )
            );
    }

    @DisplayName("상품 정보를 수정한다")
    @Test
    void updateProduct() throws Exception {
        // given
        final ProductDto productDto = new ProductDto(1L, "치킨", "chickenUrl", 20000, "KOREAN");
        doNothing().when(productService).update(any(), any());

        // when, then
        mockMvc.perform(put("/admin/{id}", 1L)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(productDto))
                .characterEncoding(StandardCharsets.UTF_8)
            )
            .andExpect(status().isNoContent())
            .andDo(
                documentationResultHandler.document(
                    requestFields(
                        fieldWithPath("id").description("상품 아이디").ignored(),
                        fieldWithPath("name").description("상품 이름")
                            .attributes(new Attributes.Attribute(RANGE, "1-25")),
                        fieldWithPath("imageUrl").description("상품 이미지 URL").optional(),
                        fieldWithPath("price").description("상품 가격")
                            .attributes(new Attributes.Attribute(RANGE, "0-10,000,000")),
                        fieldWithPath("category").description(
                            "상품 카테고리(KOREAN, JAPANESE, CHINESE, WESTERN, SNACK, DESSERT)"))
                )
            );
    }

    @DisplayName("상품 수정 시 잘못된 정보 형식으로 들어오면 예외가 발생한다")
    @Test
    void updateProduct_fail() throws Exception {
        // given
        final ProductDto productDto = new ProductDto(1L, "", "", null, null);

        // when, then
        mockMvc.perform(put("/admin/{id}", 1L)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(productDto))
                .characterEncoding(StandardCharsets.UTF_8)
            )
            .andExpectAll(
                status().isBadRequest(),
                jsonPath("$.errorMessage",
                    containsInAnyOrder(
                        "상품 이름은 비어있을 수 없습니다.",
                        "상품 가격은 비어있을 수 없습니다.",
                        "상품 카테고리는 비어있을 수 없습니다."
                    )))
            .andDo(
                documentationResultHandler.document(
                    requestFields(
                        fieldWithPath("id").description("상품 아이디").ignored(),
                        fieldWithPath("name").description("잘못된 상품 이름"),
                        fieldWithPath("imageUrl").description("상품 이미지 URL").optional(),
                        fieldWithPath("price").description("잘못된 상품 가격"),
                        fieldWithPath("category").description("잘못된 상품 카테고리"))
                )
            );
    }

    @DisplayName("상품 정보를 삭제한다")
    @Test
    void deleteProduct() throws Exception {
        // given
        doNothing().when(productService).delete(any());

        // when, then
        mockMvc.perform(delete("/admin/{id}", 1L)
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isNoContent());
    }
}
