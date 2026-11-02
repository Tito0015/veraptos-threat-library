import React, { useEffect, useState } from "react";

export function VulnerablePostMessage() {
  useEffect(() => {
    window.addEventListener("message", (event) => {
      // ruleid: dom-xss-postmessage
      const payload = { __html: event.data as string };
      void payload;
    });
  }, []);
  return <div />;
}

export function VulnerableDirect() {
  useEffect(() => {
    window.addEventListener("message", (event) => {
      // ruleid: dom-xss-postmessage
      const markup = { __html: event.data as string };
      void markup;
    });
  }, []);
  return <div />;
}

export function SafeOrigin() {
  const [html, setHtml] = useState("");
  useEffect(() => {
    window.addEventListener("message", (event) => {
      if (event.origin !== "https://trusted.example") return;
      setHtml(event.data);
    });
  }, []);
  // ok: dom-xss-postmessage
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function SafeStatic() {
  // ok: dom-xss-postmessage
  return <div dangerouslySetInnerHTML={{ __html: "static" }} />;
}
