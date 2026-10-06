package bo.edu.devsecops.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.util.HtmlUtils;

import java.util.Map;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

    @PostMapping(value = "/preview", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> preview(@RequestBody Map<String, String> body) {
        String comment = body.getOrDefault("comment", "");
        String safeComment = HtmlUtils.htmlEscape(comment);
        String html = String.join("", "<html><body><h2>Vista previa</h2><p>", safeComment, "</p></body></html>");
        return ResponseEntity.ok(html);
    }
}
