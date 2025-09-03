/**
 * Custom Jest HTML Reporter Enhancement Script
 * Enhances the display of payload/response data in HTML test reports
 */

(function(window, document) {
  if (window.jestHtmlReporterCustomScriptLoaded) return;
  window.jestHtmlReporterCustomScriptLoaded = true;

  console.log('Custom reporter enhancement loaded');

  // Wait for DOM to be ready
  document.addEventListener('DOMContentLoaded', function() {
    enhanceTestReport();
  });

  function enhanceTestReport() {
    // Enhance console log sections
    const consoleLogSections = document.querySelectorAll('.suite-consolelog-item');

    consoleLogSections.forEach(section => {
      enhanceConsoleSection(section);
    });

    // Add custom CSS for enhanced display
    addCustomStyles();
  }

  function enhanceConsoleSection(section) {
    const message = section.querySelector('.suite-consolelog-item-message');
    if (!message) return;

    const text = message.textContent;
    if (!text) return;

    // Check if this is a structured log message
    if (text.includes('=== Test:')) {
      enhanceTestSection(section, text);
    } else if (text.includes('Input Payload:') || text.includes('Service Response:') || text.includes('Expected Response:')) {
      enhanceDataSection(section, text);
    } else if (text.includes('Test Passed:')) {
      enhanceResultSection(section, text);
    }
  }

  function enhanceTestSection(section, text) {
    const title = text.replace('=== Test: ', '').trim();

    section.innerHTML = `
      <div class="suite-consolelog-item">
        <div class="custom-test-header">
          <strong>Test Scenario:</strong> ${title}
        </div>
      </div>
    `;
  }

  function enhanceDataSection(section, text) {
    const isInput = text.includes('Input Payload:');
    const isResponse = text.includes('Service Response:');
    const isExpected = text.includes('Expected Response:');

    let label = '';
    let dataClass = '';

    if (isInput) {
      label = '📤 Input Payload';
      dataClass = 'input-data';
    } else if (isResponse) {
      label = '📥 Service Response';
      dataClass = 'response-data';
    } else if (isExpected) {
      label = '🎯 Expected Response';
      dataClass = 'expected-data';
    }

    try {
      // Extract JSON data from the text
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const jsonStr = jsonMatch[0];
        const jsonData = JSON.parse(jsonStr);

        section.innerHTML = `
          <div class="suite-consolelog-item ${dataClass}">
            <div class="data-header">
              <strong>${label}:</strong>
            </div>
            <div class="json-data">
              <pre><code>${JSON.stringify(jsonData, null, 2)}</code></pre>
            </div>
          </div>
        `;
      }
    } catch (e) {
      // If JSON parsing fails, use original content with basic enhancement
      section.innerHTML = `
        <div class="suite-consolelog-item ${dataClass}">
          <div class="data-header">
            <strong>${label}:</strong>
          </div>
          <div class="text-data">
            ${text}
          </div>
        </div>
      `;
    }
  }

  function enhanceResultSection(section, text) {
    const successMatch = text.match(/✅ (.+)/);
    const message = successMatch ? successMatch[1] : text;

    section.innerHTML = `
      <div class="suite-consolelog-item test-result-success">
        <div class="result-header">
          <span class="success-icon">✅</span>
          <strong>Result:</strong> ${message}
        </div>
      </div>
    `;
  }

  function addCustomStyles() {
    const style = document.createElement('style');
    style.textContent = `
      /* Custom test data visualization */

      .custom-test-header {
        background: linear-gradient(135deg, #2196F3, #1976D2);
        color: white;
        padding: 12px 18px;
        border-radius: 8px;
        margin-bottom: 15px;
        font-size: 16px;
        box-shadow: 0 2px 8px rgba(33, 150, 243, 0.3);
      }

      .data-header {
        background: #f8f9fa;
        color: #333;
        font-size: 14px;
        padding: 8px 12px;
        margin-bottom: 10px;
        border-left: 4px solid #2196F3;
        border-radius: 4px;
      }

      .input-data .data-header {
        background: #e3f2fd;
        border-left-color: #2196F3;
      }

      .response-data .data-header {
        background: #e8f5e8;
        border-left-color: #4caf50;
      }

      .expected-data .data-header {
        background: #f3e5f5;
        border-left-color: #9c27b0;
      }

      .json-data {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 15px;
        border-radius: 6px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        overflow-x: auto;
        position: relative;
      }

      .json-data::before {
        content: 'JSON';
        position: absolute;
        top: 10px;
        right: 10px;
        background: #333;
        color: #fff;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 10px;
        text-transform: uppercase;
      }

      .json-data pre {
        margin: 0;
        padding: 0;
        background: none;
        font-size: 13px;
        line-height: 1.4;
      }

      .text-data {
        background: #f5f5f5;
        padding: 12px;
        border-radius: 6px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        color: #424242;
        border: 1px solid #ddd;
      }

      .test-result-success {
        background: linear-gradient(135deg, #4caf50, #388e3c);
        color: white;
        padding: 12px 18px;
        border-radius: 8px;
        margin: 10px 0;
        box-shadow: 0 2px 8px rgba(76, 175, 80, 0.3);
      }

      .result-header {
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .success-icon {
        font-size: 18px;
        filter: drop-shadow(0 1px 2px rgba(0,0,0,0.3));
      }

      /* Enhance existing console log styling */
      .suite-consolelog {
        margin: 15px 0;
        padding: 15px;
        background: linear-gradient(135deg, #f8f9fa, #e9ecef);
        border: 1px solid #dee2e6;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
      }

      .suite-consolelog-header {
        color: #495057;
        font-weight: 600;
        margin-bottom: 10px;
        padding-bottom: 8px;
        border-bottom: 2px solid #dee2e6;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-size: 14px;
      }

      .suite-consolelog-item {
        padding: 10px 0;
      }

      .suite-consolelog-item:not(:last-child) {
        border-bottom: 1px solid #e9ecef;
      }

      /* Responsive design */
      @media (max-width: 768px) {
        .json-data {
          font-size: 12px;
          padding: 10px;
        }

        .custom-test-header {
          padding: 10px 15px;
          font-size: 15px;
        }

        .test-result-success {
          padding: 10px 15px;
        }
      }

      /* Syntax highlighting for JSON */
      .json-data .number { color: #b5cea8; }
      .json-data .string { color: #ce9178; }
      .json-data .boolean { color: #569cd6; }
      .json-data .null { color: #569cd6; }
      .json-data .key { color: #9cdcfe; }
    `;

    document.head.appendChild(style);
  }
})(window, document);