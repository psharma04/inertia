# AI and Inertia

TL;DR: No AI is permitted for the development of Inertia. This includes (but is not limited to) writing code or tests, writing or responding to issues or PRs, language translation, reviewing security practices in the project.

Pull Requests generated with AI will be closed without review.

---

## Why no AI?

> This is going to sound a bit like a university ethics essay, I'm sorry in advance.

If you are building a secure messaging system for users who may face state-level adversaries ([and if you think that's not you, look at what's happening in the USA right now](https://theconversation.com/filming-ice-is-legal-but-exposes-you-to-digital-tracking-heres-how-to-minimize-the-risk-273566)), your responsibility extends beyond functionality to verifiable trust. Projects like Signal demonstrate this clearly: when compelled by legal process, they were able to show they possessed virtually no user data, because [their systems were designed that way from first principles](https://signal.org/bigbrother/santaclara/). That level of assurance depends not just on what is built, but *how* it is built. Inertia follows the same philosophy: every component must be understandable, auditable, and defensible under pressure.

AI-assisted development introduces an unavoidable gap in informed trust. These systems are opaque, externally controlled, and not fully auditable. Using them in the development process implicitly extends trust to parties and mechanisms outside the project’s control. For users in high-risk environments, this is not an acceptable trade-off. They must be able to rely on a system whose properties can be explained without reference to black-box tooling.

There is also a question of accountability. Security-conscious software requires clear human ownership of every decision. AI-generated or influenced code blurs that responsibility, making it harder to attribute intent, reasoning, and potential failure points. The lessons of the [XZ Utils backdoor incident](https://en.wikipedia.org/wiki/XZ_Utils_backdoor) are directly relevant: a sophisticated, long-term supply chain compromise succeeded in part because trust and authorship became diffuse and difficult to scrutinise. In the XZ case, it was possible to isolate an individual contributor making malicious changes. Introducing AI into the development process risks compounding this problem, adding another layer where intent cannot be clearly established. AI-enabled pull requests (especially in the case of "vibe coding", where the nominal author has, by definition, never actually seen the code) make the commit author inherently untrustworthy regardless of their prior contributions to the project, since they are not the actual author of the request or code.  In a domain where mistakes or compromises can have severe real-world consequences, this ambiguity is ethically unacceptable.

Finally, this policy reflects alignment with the principles behind Reticulum and its design philosophy. The Zen of Reticulum emphasises simplicity, autonomy, and minimising reliance on centralised or opaque systems. Inertia is not just a frontend application; it involves porting and implementing security-critical components in Swift, where correctness, determinism, and full comprehension of the code are essential. Introducing AI into this process would conflict with those principles by adding opaque influences into parts of the system that must be rigorously understood. Avoiding AI is therefore a deliberate choice to preserve conceptual integrity, ensure that all security properties are derived from fully understood mechanisms, and maintain alignment with the decentralised, self-reliant ethos that Reticulum embodies.

## Not even the images?

Not even the images.

AI models are trained on datasets of real human work, almost all of which is unknowingly and unconsensually collected and used for the profit of large corporations. In the same way that AI code generation results in loss of work for software developers, AI image generation results in loss of work for artists. Additionally, the licensing and copyright implications of AI generated images are still being decided in the courts. Rather than benefitting from a system built on unlicensed creative labour, I've made a simple icon in accordance with Apple's design guidelines, which will eventually be replaced by a better one created by a real human.
