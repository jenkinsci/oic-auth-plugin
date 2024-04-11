# Contributing to the OpenID Connect Authentication Plug-in

This document provides information about contributing code to
Jenkins' OpenID Connect Authentication plug-in.

There are many ways to contribute which are more or less the same as
the [general Jenkins participation](https://www.jenkins.io/participate/)
needs. This contribution guide comes in complement to the general guidelines
and [Jenkins GitHub organization contributing guide](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md).

## Document

Good documentation is a great help for users and maintainers.
All of the plugin's documentation is written in [Github Markdown](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/quickstart-for-writing-on-github).

Github makes a good job of facilitating the modification of Markdown files: click on the `Edit file` button on any markdown file and it will guides you through the steps.
If you want to make more changes or have a nice interface, you can make changes through a [codespace](https://docs.github.com/en/codespaces): click on the `Open in codespace` to have a visual studio code in the browser.

All changes should be done in a branch, then create a pull request to propose them into the main branch.

### Editing and proofreading

Documentation is prone to typos and errors. Proofreading helps us maintain an unambiguous, good quality documentation that gives confidence in the plugin.
Some (most) of the contributors are non-native english speakers, feel free to rewrite the documentation to a more idiomatic english.

Guidelines:

- **Read through** the entire document to get a sense of the overall content and structure.<br />
  Tips: read the documenta loud to spot awkward phrasings, repetitive words, and other inconsistencies more easily
- **Check** for spelling, grammar, and punctuation errors.<br />
  Tips: spellcheck and grammar tool may not catch every errors but are a great help
- **Review** the use of technical terms and jargon to make sure they're used correctly and consistently.<br />
  Goal: replace specific terms with simpler words, provide clear explanations. 
- **Look for inconsistencies** in the content, such as conflicting information or terminology.
- **Assess document structure** to make sure the document is well organized and easy to follow.<br/>
  Goal: Ensure that headlines, sub-headlines, bullet points, and numbered lists are used effectively to break up lengthy paragraphs and improve readability.

### Add guides and walkthroughs

Configuration often requires to understand the domain and how the various parameters apply to one's own specific case.
Most people want to understand just enough for their purpose or just wants it *to work*.

The [configuration](configuration/README.md) documentation contains space for addressing known providers.
Contributing to document a specific provider involves:

- describing the setup on the provider side: not the install step, only the necessary steps to configure the client
- describing the setup on the plugin side: the specific features that can be actived or that need to be disabled
- provide a JCasC sample with placeholders
- link with known issues, quastions and workarounds related to the specific provider
