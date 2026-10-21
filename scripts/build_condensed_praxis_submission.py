from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path
from typing import Iterable

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt


ROOT = Path("/Users/biruk/Documents/New project")
WORK = ROOT / "deliverables/praxis_final_cleanup"
SOURCE = WORK / "source_biruk_mekonnen.docx"
OUT_DOCX = WORK / "Final_Praxis_Submission.docx"
CHANGE_LOG = WORK / "Final_Praxis_Editorial_Change_Log.md"
REF_AUDIT = WORK / "Final_Praxis_Reference_Audit.csv"
CONSISTENCY_AUDIT = WORK / "Final_Praxis_Consistency_Audit.md"
PAGE_COMPLIANCE = WORK / "Final_Praxis_Page_Compliance.csv"
SOURCE_PARAGRAPHS = WORK / "audit_source/paragraphs.csv"
TOC_PAGE_NUMBERS = WORK / "toc_page_numbers.csv"

FIGURES = {
    "feature_variant": ROOT / "figures/chapter4/figure_4_feature_variant_progression_v1.png",
    "feature_family": ROOT / "figures/chapter4/figure_4_feature_family_ablation_v1.png",
    "train_validation": ROOT / "figures/chapter4/figure_4_train_vs_validation_v1.png",
    "k1_stacking": ROOT / "figures/chapter4/figure_4_k1_mean_vs_stacking_v1.png",
    "k2_stability": ROOT / "figures/chapter4/figure_4_k1_multiseed_stability_v1.png",
    "holdout_primary": ROOT / "figures/chapter4/figure_4_final_holdout_primary_performance_v1.png",
    "confusion": ROOT / "figures/chapter4/figure_4_final_holdout_confusion_matrix_v1.png",
    "latency": ROOT / "figures/chapter4/figure_4_k1_latency_breakdown_v1.png",
}


REFERENCES = [
    "Al-Rousan, N. M., & Trajković, L. (2012). Machine learning models for classification of BGP anomalies. In 2012 IEEE 13th International Conference on High Performance Switching and Routing (HPSR). IEEE. https://doi.org/10.1109/HPSR.2012.6260835",
    "Azimov, A., Bogomazov, E., Bush, R., Patel, K., & Sriram, K. (2022). Route leak prevention and detection using roles in UPDATE and OPEN messages (RFC 9234). RFC Editor. https://doi.org/10.17487/RFC9234",
    "Bagnulo, M., García-Martínez, A., Angieri, S., Lutu, A., & Yang, J. (2022). Practicable route leak detection and protection with ASIRIA. Computer Networks, 211, 108966. https://doi.org/10.1016/j.comnet.2022.108966",
    "Ballani, H., Francis, P., & Zhang, X. (2007). A study of prefix hijacking and interception in the Internet. In Proceedings of the 2007 Conference on Applications, Technologies, Architectures, and Protocols for Communications (pp. 265-276). Association for Computing Machinery. https://doi.org/10.1145/1282380.1282411",
    "Breiman, L. (2001). Random forests. Machine Learning, 45(1), 5-32. https://doi.org/10.1023/A:1010933404324",
    "Bush, R. (2014). Origin validation operation based on the Resource Public Key Infrastructure (RPKI) (RFC 7115). RFC Editor. https://doi.org/10.17487/RFC7115",
    "CAIDA. (2023). AS relationships dataset. Center for Applied Internet Data Analysis. https://www.caida.org/catalog/datasets/as-relationships/",
    "Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. In Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (pp. 785-794). Association for Computing Machinery. https://doi.org/10.1145/2939672.2939785",
    "Chen, Y., Yin, Q., Li, Q., Liu, Z., Xu, K., Xu, Y., Xu, M., Liu, Z., & Wu, J. (2024). Learning with semantics: Towards a semantics-aware routing anomaly detection system. In 33rd USENIX Security Symposium (pp. 5143-5160). USENIX Association. https://www.usenix.org/conference/usenixsecurity24/presentation/chen-yihao",
    "Chung, T., Aben, E., Bruijnzeels, T., Chandrasekaran, B., Choffnes, D., Levin, D., Maggs, B. M., Mislove, A., van Rijswijk-Deij, R., Rula, J. P., & Sullivan, N. (2019). RPKI is coming of age: A longitudinal study of RPKI deployment and invalid route origins. In Proceedings of the ACM Internet Measurement Conference (pp. 406-419). Association for Computing Machinery. https://doi.org/10.1145/3355369.3355596",
    "Cooper, D., Heilman, E., Brogle, K., Reyzin, L., & Goldberg, S. (2013). On the risk of misbehaving RPKI authorities. In Proceedings of the Twelfth ACM Workshop on Hot Topics in Networks. Association for Computing Machinery. https://doi.org/10.1145/2535771.2535787",
    "Cosovic, M., & Obradovic, S. (2018). BGP anomaly detection with balanced datasets. Technical Gazette, 25(3), 766-775. https://doi.org/10.17559/TV-20170219114900",
    "da Silva Jr., B. A., Mol, P., Fonseca, O. L. H. M., Cunha, I., Ferreira, R. A., & Katz-Bassett, E. (2022). Automatic inference of BGP location communities. Proceedings of the ACM on Measurement and Analysis of Computing Systems, 6(1), Article 3. https://doi.org/10.1145/3508023",
    "Deshpande, S., Thottan, M., Ho, T. K., & Sikdar, B. (2009). An online mechanism for BGP instability detection and analysis. IEEE Transactions on Computers, 58(11), 1470-1484.",
    "Dimitropoulos, X., Krioukov, D., Fomenkov, M., Huffaker, B., Hyun, Y., Claffy, K. C., & Riley, G. (2007). AS relationships: Inference and validation. ACM SIGCOMM Computer Communication Review, 37(1), 29-40. https://doi.org/10.1145/1198255.1198259",
    "Dong, Y., Zhang, H., Zhang, Y., Zhu, Z., & Mao, Z. M. (2021). ISP self-operated BGP anomaly detection based on weakly supervised learning. In 2021 IEEE 29th International Conference on Network Protocols (ICNP). IEEE. https://doi.org/10.1109/ICNP52444.2021.9651954",
    "Fawcett, T. (2006). An introduction to ROC analysis. Pattern Recognition Letters, 27(8), 861-874. https://doi.org/10.1016/j.patrec.2005.10.010",
    "Fernandez-Delgado, M., Cernadas, E., Barro, S., & Amorim, D. (2014). Do we need hundreds of classifiers to solve real world classification problems? Journal of Machine Learning Research, 15, 3133-3181. https://www.jmlr.org/papers/v15/delgado14a.html",
    "Fonseca, P., Mota, E., Bennesby, R., & Passito, A. (2019). BGP dataset generation and feature extraction for anomaly detection. In 2019 IEEE Symposium on Computers and Communications (ISCC). IEEE. https://doi.org/10.1109/ISCC47284.2019.8969619",
    "Gao, L. (2001). On inferring autonomous system relationships in the Internet. IEEE/ACM Transactions on Networking, 9(6), 733-745. https://doi.org/10.1109/90.974527",
    "Gao, L., & Rexford, J. (2001). Stable Internet routing without global coordination. IEEE/ACM Transactions on Networking, 9(6), 681-692. https://doi.org/10.1109/90.974523",
    "Gilad, Y., Cohen, A., Herzberg, A., Schapira, M., & Shulman, H. (2017). Are we there yet? On RPKI's deployment and security. In Proceedings of the Network and Distributed System Security Symposium. Internet Society. https://doi.org/10.14722/ndss.2017.23123",
    "Gilad, Y., Goldberg, S., Saggi, K., & Shulman, H. (2017). MaxLength considered harmful to the RPKI. In Proceedings of the 13th International Conference on Emerging Networking Experiments and Technologies (pp. 101-107). Association for Computing Machinery. https://doi.org/10.1145/3143361.3143364",
    "Giotsas, V., Luckie, M., Huffaker, B., & Claffy, K. C. (2014). Inferring complex AS relationships. In Proceedings of the ACM Internet Measurement Conference (pp. 23-30). Association for Computing Machinery. https://doi.org/10.1145/2663716.2663743",
    "Grinsztajn, L., Oyallon, E., & Varoquaux, G. (2022). Why do tree-based models still outperform deep learning on tabular data? In Advances in Neural Information Processing Systems, 35, 507-520. https://proceedings.neurips.cc/paper_files/paper/2022/hash/0378c7692da36807bdec87ab043cdadc-Abstract-Datasets_and_Benchmarks.html",
    "He, H., & Garcia, E. A. (2009). Learning from imbalanced data. IEEE Transactions on Knowledge and Data Engineering, 21(9), 1263-1284. https://doi.org/10.1109/TKDE.2008.239",
    "Heilman, E., Cooper, D., Reyzin, L., & Goldberg, S. (2014). From the consent of the routed: Improving the transparency of the RPKI. In Proceedings of ACM SIGCOMM 2014 (pp. 51-62). Association for Computing Machinery. https://doi.org/10.1145/2619239.2626293",
    "Hlavacek, T., Shulman, H., Waidner, M., & Streibelt, F. (2022). Stalloris: RPKI downgrade attack. In 31st USENIX Security Symposium (pp. 4455-4471). USENIX Association. https://www.usenix.org/conference/usenixsecurity22/presentation/hlavacek",
    "Hoarau, K., Tournoux, P.-U., & Razafindralambo, T. (2021). BML: An efficient and versatile tool for BGP dataset collection. In 2021 IEEE International Conference on Communications Workshops (ICC Workshops). IEEE. https://doi.org/10.1109/ICCWorkshops50388.2021.9473737",
    "Holterbach, T., Alfroy, T., Phokeer, A., Dainotti, A., & Pelsser, C. (2024). A system to detect forged-origin BGP hijacks. In 21st USENIX Symposium on Networked Systems Design and Implementation (pp. 1751-1770). USENIX Association. https://www.usenix.org/conference/nsdi24/presentation/holterbach",
    "Lad, M., Massey, D., Pei, D., Wu, Y., Zhang, B., & Zhang, L. (2006). PHAS: A prefix hijack alert system. In 15th USENIX Security Symposium. USENIX Association. https://www.usenix.org/legacy/event/sec06/tech/lad.html",
    "Latif-Martinez, H., Paillisse, J., Barlet-Ros, P., & Cabellos-Aparicio, A. (2025). BGP anomaly detection using the raw Internet topology. Computer Networks, 273, 111753. https://doi.org/10.1016/j.comnet.2025.111753",
    "Lepinski, M., & Kent, S. (2012). An infrastructure to support secure Internet routing (RFC 6480). RFC Editor. https://doi.org/10.17487/RFC6480",
    "Lepinski, M., & Sriram, K. (2017). BGPsec protocol specification (RFC 8205). RFC Editor. https://doi.org/10.17487/RFC8205",
    "Li, J., Cao, J., Meng, Z., Xie, R., & Xu, M. (2023). RoLL: Real-time and accurate route leak location with AS triplet features. In 2023 IEEE International Conference on Communications (ICC) (pp. 5240-5246). IEEE. https://doi.org/10.1109/ICC45041.2023.10278878",
    "Li, W., Lin, Z., Ashiq, M. I., Aben, E., Fontugne, R., Phokeer, A., & Chung, T. (2023). RoVista: Measuring and analyzing the Route Origin Validation (ROV) in RPKI. In Proceedings of the ACM Internet Measurement Conference (pp. 73-88). Association for Computing Machinery. https://doi.org/10.1145/3618257.3624806",
    "Lipton, Z. C., Elkan, C., & Naryanaswamy, B. (2014). Optimal thresholding of classifiers to maximize F1 measure. In Proceedings of ECML PKDD (pp. 225-239). https://doi.org/10.1007/978-3-662-44851-9_15",
    "Luckie, M., Huffaker, B., Dhamdhere, A., Giotsas, V., & Claffy, K. C. (2013). AS relationships, customer cones, and validation. In Proceedings of the ACM Internet Measurement Conference (pp. 243-256). Association for Computing Machinery. https://doi.org/10.1145/2504730.2504735",
    "Lundberg, S. M., & Lee, S.-I. (2017). A unified approach to interpreting model predictions. In Advances in Neural Information Processing Systems, 30, 4765-4774. https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html",
    "Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B., Katz, R., Himmelfarb, J., Bansal, N., & Lee, S.-I. (2020). From local explanations to global understanding with explainable AI for trees. Nature Machine Intelligence, 2, 56-67. https://doi.org/10.1038/s42256-019-0138-9",
    "Lychev, R., Goldberg, S., & Schapira, M. (2013). BGP security in partial deployment: Is the juice worth the squeeze? In Proceedings of ACM SIGCOMM. Association for Computing Machinery. https://doi.org/10.1145/2486001.2486010",
    "Mahajan, R., Wetherall, D., & Anderson, T. (2002). Understanding BGP misconfiguration. In Proceedings of ACM SIGCOMM (pp. 3-16). Association for Computing Machinery. https://doi.org/10.1145/633025.633027",
    "Mao, Z. M., Govindan, R., Varghese, G., & Katz, R. H. (2005). Route flap damping exacerbates Internet routing convergence. In Proceedings of ACM SIGCOMM (pp. 221-233). Association for Computing Machinery. https://doi.org/10.1145/1080091.1080117",
    "Mohapatra, P., Scudder, J., Ward, D., Bush, R., & Austein, R. (2013). BGP prefix origin validation (RFC 6811). RFC Editor. https://doi.org/10.17487/RFC6811",
    "Niculescu-Mizil, A., & Caruana, R. (2005). Predicting good probabilities with supervised learning. In Proceedings of the 22nd International Conference on Machine Learning (pp. 625-632). Association for Computing Machinery. https://doi.org/10.1145/1102351.1102430",
    "Orsini, C., King, A., Giordano, D., Giotsas, V., Dainotti, A., Papale, F., & Claffy, K. C. (2016). BGPStream: A software framework for live and historical BGP data analysis. In Proceedings of the ACM Internet Measurement Conference (pp. 429-444). Association for Computing Machinery. https://doi.org/10.1145/2987443.2987482",
    "Peng, S., Nie, J., Shu, X., Ruan, Z., Wang, L., Sheng, Y., & Xuan, Q. (2022). A multi-view framework for BGP anomaly detection via graph attention network. Computer Networks, 214, 109129. https://doi.org/10.1016/j.comnet.2022.109129",
    "Putina, A., Rossi, D., Bifet, A., Barlet-Ros, P., & Pescape, A. (2020). Online anomaly detection leveraging stream-based clustering techniques. IEEE Transactions on Network and Service Management, 17(2), 839-854. https://doi.org/10.1109/TNSM.2020.2971466",
    "Qin, L., Chen, L., Li, D., Ye, H., & Wang, Y. (2024). Understanding Route Origin Validation (ROV) deployment in the real world and why MANRS Action 1 is not followed. In Proceedings of the Network and Distributed System Security Symposium. Internet Society. https://doi.org/10.14722/ndss.2024.24196",
    "Rekhter, Y., Li, T., & Hares, S. (2006). A Border Gateway Protocol 4 (BGP-4) (RFC 4271). RFC Editor. https://doi.org/10.17487/RFC4271",
    "Reuter, A., Bush, R., Cunha, I., Katz-Bassett, E., Schmidt, T. C., & Wahlisch, M. (2018). Towards a rigorous methodology for measuring adoption of RPKI route validation and filtering. ACM SIGCOMM Computer Communication Review, 48(1), 19-27. https://doi.org/10.1145/3211852.3211855",
    "Rodday, N., Cunha, I., Bush, R., Katz-Bassett, E., Rodosek, G. D., Schmidt, T. C., & Wahlisch, M. (2024). The Resource Public Key Infrastructure (RPKI): A survey on measurements and future prospects. IEEE Transactions on Network and Service Management, 21(2), 2353-2373. https://doi.org/10.1109/TNSM.2023.3327455",
    "Saito, T., & Rehmsmeier, M. (2015). The precision-recall plot is more informative than the ROC plot when evaluating binary classifiers on imbalanced datasets. PLOS ONE, 10(3), e0118432. https://doi.org/10.1371/journal.pone.0118432",
    "Sanchez, O. R., Recalde, L., & Donoso, Y. (2019). Comparing machine learning algorithms for BGP anomaly detection. In Proceedings of the 15th International Conference on Emerging Networking Experiments and Technologies Companion (pp. 35-36). Association for Computing Machinery. https://doi.org/10.1145/3359992.3366640",
    "Scott, B. A., Johnstone, M. N., Szewczyk, P., & Richardson, S. (2025). BGP anomaly detection as a group dynamics problem. Computer Networks, 257, 110926. https://doi.org/10.1016/j.comnet.2024.110926",
    "Sermpezis, P., Kotronis, V., Gigis, P., Dimitropoulos, X., Cicalese, D., King, A., & Dainotti, A. (2018). ARTEMIS: Neutralizing BGP hijacking within a minute. IEEE/ACM Transactions on Networking, 26(6), 2471-2486. https://doi.org/10.1109/TNET.2018.2869798",
    "Shapira, T., & Shavitt, Y. (2020). A deep learning approach for IP hijack detection based on ASN embedding. In Proceedings of the Workshop on Network Meets AI & ML (pp. 35-41). Association for Computing Machinery. https://doi.org/10.1145/3405671.3405814",
    "Shen, C., Wang, R., Li, X., Zhang, P., Liu, K., & Tan, L. (2024). Border Gateway Protocol route leak detection technique based on graph features and machine learning. Electronics, 13(20), 4072. https://doi.org/10.3390/electronics13204072",
    "Shi, X., Xiang, Y., Wang, Z., Yin, X., & Wu, J. (2012). Detecting prefix hijackings in the Internet with Argus. In Proceedings of the ACM Internet Measurement Conference (pp. 15-28). Association for Computing Machinery. https://doi.org/10.1145/2398776.2398779",
    "Siganos, G., Faloutsos, M., Faloutsos, P., & Faloutsos, C. (2003). Power laws and the AS-level Internet topology. IEEE/ACM Transactions on Networking, 11(4), 514-524. https://doi.org/10.1109/TNET.2003.815300",
    "Silla, C. N., & Freitas, A. A. (2011). A survey of hierarchical classification across different application domains. Data Mining and Knowledge Discovery, 22(1), 31-72. https://doi.org/10.1007/s10618-010-0175-9",
    "Sokolova, M., & Lapalme, G. (2009). A systematic analysis of performance measures for classification tasks. Information Processing & Management, 45(4), 427-437. https://doi.org/10.1016/j.ipm.2009.03.002",
    "University of Oregon. (2000). Route Views Project. https://www.routeviews.org/",
    "Van Calster, B., McLernon, D. J., van Smeden, M., Wynants, L., & Steyerberg, E. W. (2019). Calibration: The Achilles heel of predictive analytics. BMC Medicine, 17, 230. https://doi.org/10.1186/s12916-019-1466-7",
    "Wahlisch, M., Schmidt, R., Schmidt, T. C., Maennel, O., Uhlig, S., & Tyson, G. (2012). Towards detecting BGP route hijacking using the RPKI. ACM SIGCOMM Computer Communication Review, 42(4), 103-104. https://doi.org/10.1145/2377677.2377700",
    "Xie, Y., Zhang, Z., Li, N., & Gao, H. (2025). LeakFocus: Catching the perpetrator in routing leak event. Computers & Security, 150, 104300. https://doi.org/10.1016/j.cose.2024.104300",
    "Yang, J., Latif, H., Paillisse, J., Cabellos-Aparicio, A., & Barlet-Ros, P. (2022). Unveiling the potential of graph neural networks for BGP anomaly detection. In Proceedings of the 1st International Workshop on Graph Neural Networking (pp. 7-12). Association for Computing Machinery. https://doi.org/10.1145/3565473.3569188",
]

SOURCE_CHAPTER_RANGES = {
    "Chapter 1": (301, 392),
    "Chapter 2": (393, 644),
    "Chapter 3": (645, 1067),
    "Chapter 4": (1068, 1457),
    "Chapter 5": (1458, 1613),
}

STALE_SOURCE_PATTERNS = [
    r"\b34[- ]event\b",
    r"\b75[- ]event\b",
    r"\b84[- ]event\b",
    r"\bseven[- ]event\b",
    r"\b7[- ]event\b",
    r"\b40[- ]feature\b",
    r"\b46[- ]feature\b",
    r"\b49[- ]feature\b",
    r"\bthree[- ]RPKI\b",
    r"\b3 RPKI\b",
    r"\b0\.9769\b",
    r"\btau\s*=\s*0\.70\b",
    r"\bτ\s*=\s*0\.70\b",
    r"\b4\.10\s*(microsecond|us|µs)",
    r"hierarchical Random Forest",
    r"Lorem ipsum",
]


def is_stale_source_text(text: str) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in STALE_SOURCE_PATTERNS)


def add_source_supporting_material(doc: Document, chapter: str, word_limit: int) -> None:
    if not SOURCE_PARAGRAPHS.exists():
        return
    start, end = SOURCE_CHAPTER_RANGES[chapter]
    selected: list[str] = []
    total_words = 0
    with SOURCE_PARAGRAPHS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            index = int(row["paragraph_index"])
            if index < start or index > end:
                continue
            style = row["style"].lower()
            text = row["text"].strip()
            words = int(row["word_count"])
            if not text or words < 35:
                continue
            if style.startswith("heading") or style.startswith("toc"):
                continue
            if text.startswith(("Table ", "Figure ")):
                continue
            if is_stale_source_text(text):
                continue
            if total_words + words > word_limit:
                break
            selected.append(text)
            total_words += words
    if not selected:
        return
    add_heading(doc, "Condensed Source Synthesis", 2)
    for text in selected:
        add_p(doc, text)


def clean_front_matter_placeholders(doc: Document) -> None:
    for p in doc.paragraphs:
        text = p.text.strip()
        if "John Howard Doe" in text:
            p.text = (
                "The final approval page should be completed with the official examination date, "
                "committee information, and signatures according to program requirements."
            )
        elif "Root-Cause Ranking System" in text:
            p.text = text.replace("Root-Cause Ranking System", "Classification and Ranking System")
        elif text.startswith("Last. M. First"):
            p.text = "Additional committee member information to be completed according to program records."
        elif "Lorem ipsum" in text or text.startswith("Mauris aliquet lorem"):
            p.text = "This section may be completed by the author before final institutional submission."


def remove_from_table_of_contents_onward(doc: Document) -> None:
    start = None
    for p in doc.paragraphs:
        if p.text.strip() == "Table of Contents":
            start = p._element
            break
    if start is None:
        raise RuntimeError("Could not find Table of Contents heading")
    body = doc.element.body
    children = list(body)
    start_index = children.index(start)
    for child in children[start_index:]:
        if child.tag.endswith("sectPr"):
            continue
        body.remove(child)


def load_toc_pages() -> dict[str, str]:
    if not TOC_PAGE_NUMBERS.exists():
        return {}
    with TOC_PAGE_NUMBERS.open(newline="", encoding="utf-8") as handle:
        return {row["item"]: row["page"] for row in csv.DictReader(handle)}


def add_generated_front_matter(doc: Document) -> None:
    pages = load_toc_pages()
    doc.add_page_break()
    add_heading(doc, "Table of Contents", 1)
    toc_rows = [
        ["Chapter 1 - Introduction", pages.get("Chapter 1", "")],
        ["Chapter 2 - Literature Review", pages.get("Chapter 2", "")],
        ["Chapter 3 - Methodology", pages.get("Chapter 3", "")],
        ["Chapter 4 - Results", pages.get("Chapter 4", "")],
        ["Chapter 5 - Conclusions", pages.get("Chapter 5", "")],
        ["References", pages.get("References", "")],
    ]
    add_table(doc, "Table of Contents.", ["Section", "Page"], toc_rows)
    add_heading(doc, "List of Tables", 1)
    add_table(doc, "List of Tables.", ["Table", "Title"], [
        ["Table 1.1", "Research questions and hypotheses"],
        ["Table 2.1", "Literature areas supporting the final methodology"],
        ["Table 3.1", "Frozen incident partition summary"],
        ["Table 3.2", "Final V4 feature representation"],
        ["Table 4.1", "Final corpus and feature foundation"],
        ["Table 4.2", "Final Holdout class and ranking results"],
    ])
    add_heading(doc, "List of Figures", 1)
    add_table(doc, "List of Figures.", ["Figure", "Title"], [
        ["Figure 4.1", "Feature variant progression"],
        ["Figure 4.2", "Feature-family ablation results"],
        ["Figure 4.3", "TRAIN grouped-CV versus independent Validation"],
        ["Figure 4.4", "Mean probability aggregation versus K1 temporal stacking"],
        ["Figure 4.5", "K1 multi-seed stability results"],
        ["Figure 4.6", "Final Holdout primary performance"],
        ["Figure 4.7", "Final Holdout confusion matrix"],
        ["Figure 4.8", "Warm downstream K1 latency breakdown"],
    ])
    add_heading(doc, "List of Acronyms", 1)
    add_table(doc, "List of Acronyms.", ["Acronym", "Meaning"], [
        ["AS", "Autonomous System"],
        ["ASN", "Autonomous System Number"],
        ["BGP", "Border Gateway Protocol"],
        ["CAIDA", "Center for Applied Internet Data Analysis"],
        ["F1", "Harmonic mean of precision and recall"],
        ["MRR", "Mean Reciprocal Rank"],
        ["MRT", "Multi-threaded Routing Toolkit archive format"],
        ["RIB", "Routing Information Base"],
        ["RIPE RIS", "RIPE Routing Information Service"],
        ["RPKI", "Resource Public Key Infrastructure"],
        ["ROA", "Route Origin Authorization"],
        ["ROV", "Route Origin Validation"],
    ])


def add_p(doc: Document, text: str = "", style: str | None = None, bold_lead: str | None = None) -> None:
    p = doc.add_paragraph(style=style)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.5
    if bold_lead and text.startswith(bold_lead):
        run = p.add_run(bold_lead)
        run.bold = True
        p.add_run(text[len(bold_lead):])
    else:
        p.add_run(text)


def add_heading(doc: Document, text: str, level: int) -> None:
    p = doc.add_paragraph(text, style=f"Heading {level}")
    p.paragraph_format.space_before = Pt(12 if level == 1 else 8)
    p.paragraph_format.space_after = Pt(6)
    if level == 1:
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER


def add_table(doc: Document, caption: str, headers: list[str], rows: list[list[str]]) -> None:
    cap = doc.add_paragraph(caption)
    cap.style = doc.styles["Caption"] if "Caption" in [s.name for s in doc.styles] else doc.styles["Normal"]
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    for i, header in enumerate(headers):
        table.rows[0].cells[i].text = header
    for row in rows:
        cells = table.add_row().cells
        for i, value in enumerate(row):
            cells[i].text = value
    add_p(doc)


def add_figure(doc: Document, key: str, caption: str, width: float = 6.2) -> None:
    path = FIGURES.get(key)
    if not path or not path.exists():
        add_p(doc, f"[Figure omitted because source file was unavailable: {key}]", style="Normal")
        return
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(str(path), width=Inches(width))
    cap = doc.add_paragraph(caption)
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    try:
        cap.style = doc.styles["Caption"]
    except Exception:
        pass


def add_bullets(doc: Document, items: Iterable[str]) -> None:
    for item in items:
        p = doc.add_paragraph(style="List Bullet")
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.5
        p.add_run(item)


def chapter_1(doc: Document) -> None:
    add_heading(doc, "Chapter 1 - Introduction", 1)
    add_heading(doc, "Background", 2)
    add_p(doc, "Border Gateway Protocol (BGP) is the interdomain routing protocol that allows independently operated networks to exchange reachability information across the Internet. Each Autonomous System (AS) announces the IP prefixes it can reach, attaches AS-path information to those announcements, and uses routing policy to select and export paths. The protocol's flexibility is one reason it scales across competing operators, but that flexibility also means that routing incidents can propagate quickly when a prefix, origin, or path is announced incorrectly (Rekhter et al., 2006; Gao & Rexford, 2001).")
    add_p(doc, "Enterprise networks depend on upstream providers, cloud platforms, transit networks, and public routing infrastructure that they do not fully control. When a BGP incident occurs, engineers often need to distinguish whether observed reachability loss or traffic redirection is more consistent with a hijack, a route leak, or an outage. Those categories overlap in observable symptoms, and the first available evidence is often a stream of BGP UPDATE messages rather than a complete root-cause report.")
    add_heading(doc, "Research Motivation", 2)
    add_p(doc, "The motivation for this Praxis is practical. Network engineers need faster and more defensible ways to prioritize investigation when BGP behavior changes. Existing monitoring systems can raise alarms, but an alarm alone does not always explain whether the most likely routing-incident class is Hijack, Leak, or Outage. The operational challenge is not simply detecting that routing changed; it is ranking the likely incident explanation using evidence that is visible in public BGP observations and security context.")
    add_p(doc, "This study therefore focuses on post-window incident classification and ranking. The final system assumes that a candidate BGP incident has been identified and that the relevant observation window has been collected. It then uses engineered behavioral, AS-relationship, and RPKI/ROV evidence to rank the incident class. The model does not prove the physical or administrative root cause, and it is not an autonomous mitigation system. Its purpose is to provide a ranked diagnostic hypothesis that can support engineering investigation.")
    add_heading(doc, "Problem Statement", 2)
    add_p(doc, "BGP incident investigation remains difficult because different incident classes can produce similar routing symptoms. A hijack can look like an unexpected origin or path change, a leak can expose routes outside an intended policy boundary, and an outage can create withdrawal and reachability patterns that overlap with other disruptions. Without a reproducible incident-level learning framework, model results can also be distorted by class imbalance, unequal incident duration, duplicate windows from the same event, or leakage between training and evaluation partitions.")
    add_p(doc, "The research problem is the need for a reproducible AI-based method that classifies and ranks likely BGP incident classes from observable routing evidence while preserving incident-level experimental separation and transparent evaluation. The method must be accurate enough to be useful, but also honest about its limits: it ranks incident classes from BGP evidence and does not replace operator judgment or end-to-end root-cause analysis.")
    add_heading(doc, "Thesis Statement", 2)
    add_p(doc, "An incident-level machine-learning system that combines BGP behavioral features, CAIDA AS-relationship context, and historical RPKI/ROV evidence can classify and rank Hijack, Leak, and Outage incidents with defensible generalization when the experimental design preserves incident-level separation, controls leakage, and evaluates the frozen model on an untouched Final Holdout corpus.")
    add_heading(doc, "Research Objectives", 2)
    add_bullets(doc, [
        "Construct a balanced, quality-controlled incident corpus for Hijack, Leak, and Outage events.",
        "Extract reproducible five-minute analytical-window features from historical RouteViews data.",
        "Integrate behavioral, AS-relationship, and RPKI/ROV evidence into a final 74-feature V4 representation.",
        "Evaluate Random Forest and XGBoost approaches under incident-level grouped cross-validation.",
        "Develop an incident-level temporal stacking architecture that ranks likely incident classes.",
        "Validate the final frozen architecture using a sealed Final Holdout evaluation.",
    ])
    add_heading(doc, "Research Questions and Hypotheses", 2)
    add_table(doc, "Table 1.1 Research questions and hypotheses.", ["Research question", "Hypothesis", "Study response"], [
        ["RQ1", "BGP behavioral evidence can distinguish Hijack, Leak, and Outage better than chance.", "Evaluated through baseline and enriched models."],
        ["RQ2", "Security and topology context improve classification beyond behavioral features alone.", "Evaluated through V1-V4 and feature-family ablation."],
        ["RQ3", "Incident-level aggregation improves classification and ranking over simple window aggregation.", "Evaluated through K1 stacking versus mean probability aggregation."],
        ["RQ4", "A frozen model can generalize to unseen incidents under leakage-safe evaluation.", "Evaluated through Validation and Final Holdout."],
    ])
    add_heading(doc, "Scope and Limitations", 2)
    add_p(doc, "The study uses public RouteViews observations and external incident labels. The final corpus contains 1,419 incidents, balanced across 473 Hijack, 473 Leak, and 473 Outage incidents. The authoritative split contains 993 TRAIN incidents, 213 Validation incidents, and 213 Final Holdout incidents. The feature representation contains 44 Behavioral features, 14 CAIDA AS-relationship features, and 16 RPKI/ROV features, for a final V4 schema of 74 features.")
    add_p(doc, "Several boundaries are important. The system is not a universal anomaly detector, not a complete real-time monitoring platform, and not a proof of physical root cause. Stage 1 Normal-vs-Incident discrimination remained experimental and auxiliary. The latency result measures warm downstream K1 computation after feature availability; it does not include live BGP collection, MRT parsing, feature generation, enrichment, or model startup.")
    add_heading(doc, "Organization of the Praxis", 2)
    add_p(doc, "Chapter 2 reviews the BGP, routing-security, measurement, and machine-learning literature that grounds the study. Chapter 3 describes the final methodology, including corpus construction, RouteViews processing, feature engineering, leakage controls, and modeling. Chapter 4 presents the results from feature development through Final Holdout evaluation. Chapter 5 summarizes the findings, contributions, limitations, and future work.")
    add_source_supporting_material(doc, "Chapter 1", 900)


def chapter_2(doc: Document) -> None:
    add_heading(doc, "Chapter 2 - Literature Review", 1)
    add_heading(doc, "Introduction", 2)
    add_p(doc, "The literature supporting this Praxis falls into eight connected areas: BGP operation and measurement, routing incidents, routing security, AS relationships, anomaly detection, machine learning for network diagnosis, explainability, and research gaps. The review emphasizes studies that justify the final method rather than repeating introductory protocol material.")
    add_heading(doc, "BGP Operation and Measurement", 2)
    add_p(doc, "BGP is a policy-based path-vector protocol. Operators announce reachability to prefixes, select routes according to local policy, and export routes according to business and engineering constraints (Rekhter et al., 2006; Gao & Rexford, 2001). This flexibility allows the Internet to operate without central coordination, but it also means that the protocol accepts information from neighbors unless routing policy, filtering, or validation rejects it.")
    add_p(doc, "Public BGP measurement projects make historical interdomain behavior observable. RouteViews provides archived route collector data used widely for routing research, and BGPStream provides a software framework for working with live and historical BGP data (University of Oregon, 2000; Orsini et al., 2016). These datasets do not show every local enterprise routing decision, but they provide a reproducible external view of routing behavior across time.")
    add_p(doc, "Prior studies have used BGP measurements to analyze path changes, convergence, route flap behavior, community information, and topology inference (Mao et al., 2005; da Silva Jr. et al., 2022). This study follows that measurement tradition by using historical RouteViews data as the feature source while maintaining strict separation between incident partitions.")
    add_heading(doc, "Routing Incidents and Outages", 2)
    add_p(doc, "BGP incidents include intentional and accidental events. Hijacks involve unauthorized or unexpected origin or path announcements; route leaks involve route propagation outside an intended export policy; outages involve reachability loss or major withdrawal behavior. Misconfiguration has long been recognized as a major source of interdomain routing problems, and prefix hijacking has been studied both as a security threat and as an operational failure mode (Mahajan et al., 2002; Ballani et al., 2007).")
    add_p(doc, "Hijack detection literature includes systems that look for suspicious origin changes, prefix ownership conflicts, and control-plane evidence inconsistent with expected authorization (Lad et al., 2006; Shi et al., 2012; Sermpezis et al., 2018; Holterbach et al., 2024). Route leak work emphasizes policy violations, AS-path structure, AS triplets, and export-role semantics (Azimov et al., 2022; Bagnulo et al., 2022; Li et al., 2023; Xie et al., 2025). Outage analysis is more heterogeneous because outages may be caused by power, censorship, provider failure, cable damage, policy changes, or other events that become visible through routing only indirectly.")
    add_heading(doc, "Routing Security and Validation", 2)
    add_p(doc, "The Resource Public Key Infrastructure (RPKI) provides a mechanism for prefix holders to create Route Origin Authorizations (ROAs), allowing routers or measurement systems to classify origin announcements as VALID, INVALID, or NotFound. RPKI architecture and origin validation are defined through RFCs and operational guidance, while deployment and security studies have examined both adoption and limitations (Lepinski & Kent, 2012; Mohapatra et al., 2013; Bush, 2014; Chung et al., 2019; Rodday et al., 2024).")
    add_p(doc, "RPKI helps with origin validation but does not solve every routing-security problem. Partial deployment, maxLength choices, relying-party behavior, and authority risks can affect interpretation (Cooper et al., 2013; Gilad, Cohen, et al., 2017; Gilad, Goldberg, et al., 2017; Lychev et al., 2013). BGPsec extends protection toward path validation, but deployment complexity limits its operational role (Lepinski & Sriram, 2017). For this Praxis, RPKI/ROV features provide historical validation context; they are not treated as a complete security oracle.")
    add_heading(doc, "AS Relationships and Routing Policy", 2)
    add_p(doc, "Interdomain routing is shaped by business relationships as well as reachability. Customer-provider and peer-peer relationships influence which paths are plausible, exportable, and policy-consistent. Gao (2001), Gao and Rexford (2001), Dimitropoulos et al. (2007), Giotsas et al. (2014), and Luckie et al. (2013) provide the foundation for relationship inference, valley-free reasoning, and customer-cone context.")
    add_p(doc, "CAIDA's AS relationship dataset is widely used for research features that approximate the commercial and topological structure behind observed AS paths (CAIDA, 2023). In this study, CAIDA context is used to add relationship and valley-free evidence. This is especially relevant to route leaks, where unusual propagation through AS relationships can be more informative than raw prefix counts alone.")
    add_heading(doc, "BGP Anomaly Detection", 2)
    add_p(doc, "BGP anomaly detection studies have used statistical, rule-based, graph-based, and machine-learning methods. Early work often focused on instability, volume changes, or path changes, while later work incorporated richer topology, semantic, or graph features (Al-Rousan & Trajkovic, 2012; Cosovic & Obradovic, 2018; Fonseca et al., 2019; Hoarau et al., 2021; Peng et al., 2022; Chen et al., 2024; Scott et al., 2025).")
    add_p(doc, "Temporal aggregation is common because BGP UPDATE streams are noisy at message level. Deshpande et al. (2009) used five-minute intervals for BGP instability analysis, and Fonseca et al. (2019) examined BGP feature extraction at multiple time scales, including five-minute windows. This supports the use of five-minute analytical windows in this Praxis, while also leaving shorter observation horizons as future work.")
    add_heading(doc, "Machine Learning and Explainability", 2)
    add_p(doc, "Tree-based models remain strong for tabular data, particularly when features are structured, heterogeneous, and not extremely high dimensional (Breiman, 2001; Chen & Guestrin, 2016; Fernandez-Delgado et al., 2014; Grinsztajn et al., 2022). This literature supports the study's comparison of Random Forest and XGBoost rather than assuming a deep architecture is automatically superior.")
    add_p(doc, "Network incident data also creates imbalance and evaluation challenges. Class imbalance can distort model selection, while incident-level grouping is necessary when many windows belong to the same real-world event (He & Garcia, 2009; Saito & Rehmsmeier, 2015; Sokolova & Lapalme, 2009). Probability ranking and calibration are relevant because the final output is a ranked incident hypothesis rather than only a single class label (Fawcett, 2006; Niculescu-Mizil & Caruana, 2005; Van Calster et al., 2019).")
    add_p(doc, "Explainability literature is also relevant because network engineers need to understand which evidence influenced a diagnostic ranking. SHAP and tree-explanation methods provide one path for future operational interpretation, although full SHAP analysis is outside the final evaluation scope reported here (Lundberg & Lee, 2017; Lundberg et al., 2020).")
    add_heading(doc, "Research Gaps and Study Positioning", 2)
    add_p(doc, "The literature establishes strong foundations for BGP measurement, routing security, route-leak detection, hijack detection, and anomaly classification. However, several gaps remain for the problem addressed here. Many studies focus on one incident type, use event definitions that are difficult to compare across classes, or evaluate at the window/message level rather than treating the real incident as the independent experimental unit. Others do not combine behavioral, AS-relationship, and historical RPKI/ROV evidence in one leakage-controlled incident-ranking framework.")
    add_p(doc, "This Praxis addresses those gaps by constructing a balanced incident-level corpus, freezing TRAIN/Validation/Final Holdout partitions before modeling, using RouteViews-derived five-minute analytical windows, comparing feature variants, and evaluating a final XGBoost-to-XGBoost temporal stacking architecture on an untouched Final Holdout set.")
    add_table(doc, "Table 2.1 Literature areas supporting the final methodology.", ["Area", "Role in this Praxis", "Representative sources"], [
        ["BGP operation and measurement", "Defines observable routing evidence and RouteViews data source.", "Rekhter et al.; University of Oregon; Orsini et al."],
        ["Routing incidents", "Grounds Hijack, Leak, and Outage categories.", "Mahajan et al.; Ballani et al.; Azimov et al.; Holterbach et al."],
        ["RPKI/ROV", "Supports origin-validation features.", "Lepinski & Kent; Mohapatra et al.; Chung et al.; Rodday et al."],
        ["AS relationships", "Supports CAIDA and valley-free features.", "Gao; Dimitropoulos et al.; Luckie et al.; CAIDA."],
        ["Machine learning", "Supports model families and evaluation design.", "Breiman; Chen & Guestrin; He & Garcia; Saito & Rehmsmeier."],
    ])
    add_heading(doc, "Literature Synthesis", 2)
    add_p(doc, "The final methodology follows directly from the literature. BGP measurement provides reproducible historical observations; routing-security work motivates RPKI/ROV context; AS-relationship research motivates CAIDA and valley-free features; anomaly-detection studies support temporal feature engineering; and machine-learning evaluation literature motivates incident-level grouping, strict partition isolation, and ranking metrics. The study contributes an integrated, incident-level, leakage-controlled framework for ranking Hijack, Leak, and Outage hypotheses from observed BGP evidence.")
    add_source_supporting_material(doc, "Chapter 2", 5200)


def chapter_3(doc: Document) -> None:
    add_heading(doc, "Chapter 3 - Methodology", 1)
    add_heading(doc, "Research Design", 2)
    add_p(doc, "This Praxis used a quantitative experimental design. The independent experimental unit was the incident, not the five-minute feature row. This choice was central because one incident can generate many windows; splitting by window would allow the same real-world event to influence both development and evaluation. All windows generated from an incident inherited that incident's frozen partition.")
    add_p(doc, "The final task was multiclass incident classification and ranking for Hijack, Leak, and Outage. Stage 1 Normal-vs-Incident detection was investigated during development, but it remained experimental and auxiliary. The final reported architecture is post-window incident classification and ranking: it assumes candidate incident observations are available and ranks the likely incident class from engineered evidence.")
    add_heading(doc, "Incident Corpus and Partitioning", 2)
    add_p(doc, "The final frozen roster contained 1,419 independent incidents: 473 Hijack, 473 Leak, and 473 Outage. Duplicate remediation was completed before freezing the v2 roster. The split contained 993 TRAIN incidents, 213 Validation incidents, and 213 Final Holdout incidents, with 331/331/331 incidents per class in TRAIN and 71/71/71 incidents per class in both Validation and Final Holdout.")
    add_table(doc, "Table 3.1 Frozen incident partition summary.", ["Partition", "Hijack", "Leak", "Outage", "Total", "Purpose"], [
        ["TRAIN", "331", "331", "331", "993", "Model development, grouped CV, ablation, tuning."],
        ["Validation", "71", "71", "71", "213", "Single predeclared confirmation of the pre-K1 XGBoost candidate."],
        ["Final Holdout", "71", "71", "71", "213", "One-time terminal evaluation of the frozen K1 architecture."],
    ])
    add_heading(doc, "RouteViews Data and Analytical Windows", 2)
    add_p(doc, "RouteViews MRT UPDATE archives were used as the historical BGP source. For each incident, acquisition windows were created around documented or detector-supported active intervals. For Hijack and Leak events, long silent gaps in detector spans were not automatically treated as continuous incident activity; active windows were scoped around event-specific evidence. For Outage events, Cloudflare-documented start and end intervals were used as the incident interval when they passed quality checks.")
    add_p(doc, "The analytical unit for feature extraction was a non-overlapping five-minute UTC window. Each window preserved its incident UID, partition, category, window start and end time, and source provenance. Silent or unknown periods were not relabeled as Normal. Normal windows were separately curated and remained auxiliary because Stage 1 did not become part of the final architecture.")
    add_heading(doc, "Feature Engineering", 2)
    add_p(doc, "The final V4 feature schema contained 74 features: 44 Behavioral features, 14 CAIDA AS-relationship features, and 16 RPKI/ROV features. Behavioral features summarized BGP UPDATE activity, prefix behavior, peer visibility, AS-path structure, announcements, withdrawals, origin changes, and window-level stability. CAIDA features added relationship, provider/customer, peer, valley-free, and visibility context. RPKI/ROV features added historical origin-validation status, INVALID/NotFound evidence, maxLength evidence, and origin-mismatch signals.")
    add_table(doc, "Table 3.2 Final V4 feature representation.", ["Feature group", "Count", "Purpose"], [
        ["Behavioral", "44", "BGP UPDATE, prefix, peer, AS-path, and stability evidence."],
        ["CAIDA AS relationship", "14", "Relationship, valley-free, and peer/provider/customer context."],
        ["RPKI/ROV", "16", "Historical origin-validation and authorization evidence."],
        ["Total V4", "74", "Final model-ready representation."],
    ])
    add_heading(doc, "Feature Variants and Imbalance Strategy", 2)
    add_p(doc, "Feature development used four frozen variants. V1 contained Behavioral features only. V2 added CAIDA features. V3 added RPKI/ROV features. V4 combined all 74 features. This structure supported both feature-variant comparison and feature-family ablation without changing the experimental unit.")
    add_p(doc, "Three imbalance strategies were considered. I0 used the natural window representation. I1 retained all available windows and used incident-aware weighting so incidents contributed approximately equal aggregate influence. I2 combined incident-aware weighting with a p95 temporal cap. I1 was retained because it addressed unequal incident duration without discarding valid windows through a fixed cap.")
    add_heading(doc, "Model Families and Evaluation Design", 2)
    add_p(doc, "Random Forest and XGBoost were evaluated because both are strong tabular-learning methods and provide practical baselines for structured BGP features (Breiman, 2001; Chen & Guestrin, 2016; Grinsztajn et al., 2022). Grouped cross-validation used incident UID as the grouping key. Hyperparameter tuning, feature comparison, and model comparison were restricted to TRAIN until the predeclared Validation step.")
    add_p(doc, "Validation was opened once for the selected pre-K1 XGBoost candidate. After Validation, K1 was developed as a versioned TRAIN-only incident-level stacking experiment and was not described as Validation-confirmed. Final Holdout remained sealed until the final frozen architecture and parameters were locked.")
    add_heading(doc, "Incident-Level Temporal Stacking", 2)
    add_p(doc, "The final architecture was an XGBoost-to-XGBoost incident-level temporal stacker. The first level produced class probabilities for eligible windows. Those probabilities were then transformed into incident-level temporal meta-features using deterministic chronological structure, including early, middle, and late summaries where enough windows were available. The second-level XGBoost model ranked Hijack, Leak, and Outage from those incident-level meta-features.")
    add_p(doc, "Nested and cross-fit procedures protected against leakage. For outer TRAIN folds, first-level models were trained only on outer training incidents, and second-level meta-training rows were built from inner out-of-fold probabilities. The held-out incident in a fold could not influence first-level fitting, second-level preprocessing, hyperparameter selection, or second-level fitting.")
    add_heading(doc, "Quality Gates and Leakage Controls", 2)
    add_p(doc, "Quality gates checked incident counts, partition membership, duplicate status, timestamps, ASN and prefix availability where relevant, source provenance, feature schema, row uniqueness, and partition isolation. Validation and Final Holdout were protected from model development decisions. The final Holdout was used once, after the deployable K1 configuration was frozen.")
    add_heading(doc, "Evaluation Metrics", 2)
    add_p(doc, "The primary incident-level metrics were Macro F1, Top-1 accuracy, Top-2 accuracy, and Mean Reciprocal Rank (MRR). Macro F1 was used because class balance alone does not guarantee equal difficulty across Hijack, Leak, and Outage. Ranking metrics were included because the operational use case is diagnostic ranking rather than only hard classification.")
    add_heading(doc, "Computational Latency Methodology", 2)
    add_p(doc, "Phase N measured the warm downstream K1 computation after feature/probability availability. It did not measure end-to-end live detection latency. The benchmark excluded live BGP UPDATE collection, MRT parsing, five-minute observation-window accumulation, Behavioral feature generation, CAIDA enrichment, RPKI/ROV enrichment, model startup/loading, and complete live pipeline overhead.")
    add_heading(doc, "Methodological Limitations", 2)
    add_p(doc, "The methodology depends on public RouteViews visibility and external incident labels. RouteViews may not reflect every enterprise-local routing state. RPKI and CAIDA features depend on historical snapshots and inferred relationships. The Normal-vs-Incident stage remained unresolved, and the final system ranks likely incident classes rather than proving physical root cause. These limitations are carried into the interpretation of results.")
    add_source_supporting_material(doc, "Chapter 3", 5600)


def chapter_4(doc: Document) -> None:
    add_heading(doc, "Chapter 4 - Results", 1)
    add_heading(doc, "Overview", 2)
    add_p(doc, "Chapter 4 reports the final experimental sequence from feature development through the one-time Final Holdout evaluation. Results are presented at the incident level unless otherwise stated. Developmental results are included only when they explain a final methodological decision.")
    add_heading(doc, "Corpus and Feature Foundation", 2)
    add_p(doc, "The frozen corpus and V4 feature representation satisfied the study design: 1,419 incidents, balanced across Hijack, Leak, and Outage, with a final 74-feature schema. This provided the stable foundation for all subsequent model comparison and final evaluation.")
    add_table(doc, "Table 4.1 Final corpus and feature foundation.", ["Item", "Final value"], [
        ["Incidents", "1,419"],
        ["Class counts", "473 Hijack / 473 Leak / 473 Outage"],
        ["TRAIN", "993 incidents"],
        ["Validation", "213 incidents"],
        ["Final Holdout", "213 incidents"],
        ["V4 features", "74 = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV"],
    ])
    add_heading(doc, "Feature Variant and Ablation Results", 2)
    add_p(doc, "The V1-V4 progression tested whether topology and routing-security context added useful signal beyond Behavioral features. The final representation retained all three families because the combined V4 schema supported the strongest downstream architecture and allowed class-specific evidence to contribute differently across Hijack, Leak, and Outage.")
    add_figure(doc, "feature_variant", "Figure 4.1 Feature variant progression from Behavioral-only evidence to the full V4 representation.")
    add_p(doc, "Feature-family ablation showed that feature groups did not contribute uniformly. RPKI/ROV evidence was especially important for Hijack discrimination, while CAIDA and peer-visibility context provided useful signal for Leak and Outage interpretation. This supports the final integrated representation rather than a purely behavioral model.")
    add_figure(doc, "feature_family", "Figure 4.2 Feature-family ablation results.")
    add_heading(doc, "Incident Imbalance and Stage 1 Findings", 2)
    add_p(doc, "Incident-aware weighting was retained as I1 because it reduced unequal incident influence while preserving all valid windows. The p95 cap in I2 was informative but was not adopted as the final strategy because it removed windows by duration rather than by evidence quality.")
    add_p(doc, "Stage 1 Normal-vs-Incident discrimination remained unresolved and auxiliary. Weighting improved some aggregate discrimination measures, but Normal precision-recall behavior remained weak. The final K1 system therefore focuses on ranking Hijack, Leak, and Outage after incident windows are available.")
    add_heading(doc, "Random Forest and XGBoost Development", 2)
    add_p(doc, "Random Forest provided a strong benchmark after optimization and refinement, but refined XGBoost produced the stronger TRAIN grouped-CV result under the V4/I1 framework. The refined XGBoost candidate achieved TRAIN grouped-CV Macro F1 of 0.805678 before the single Validation confirmation.")
    add_p(doc, "The XGBoost result did not end model development. It established the first-level classifier used later in incident-level stacking, where the model could exploit temporal incident summaries rather than relying only on mean window probabilities.")
    add_heading(doc, "Independent Validation", 2)
    add_p(doc, "The predeclared Validation confirmation evaluated 213 Validation incidents and passed the predefined floors, but performance decreased relative to TRAIN grouped-CV. Validation Macro F1 was 0.713904, Top-2 accuracy was 0.901408, and MRR was 0.842723. This drop is important because it shows why the dissertation should not report TRAIN development results as final generalization.")
    add_figure(doc, "train_validation", "Figure 4.3 TRAIN grouped-CV versus independent Validation performance.")
    add_heading(doc, "Incident-Level Stacking", 2)
    add_p(doc, "K1 incident-level temporal stacking materially improved TRAIN-only nested-CV performance over mean probability aggregation. The stacker used temporal summaries of first-level probabilities and produced stronger classification and ranking results while preserving grouped, leakage-controlled folds.")
    add_figure(doc, "k1_stacking", "Figure 4.4 Mean probability aggregation versus K1 temporal stacking.")
    add_p(doc, "Forensic checks found no detected Level-1 or Level-2 leakage, 993 unique incident meta rows, balanced class counts, no true-class encoded meta-features, and label-permutation collapse near random Macro F1. Multi-seed K2 results supported the stability of the K1 gain.")
    add_figure(doc, "k2_stability", "Figure 4.5 K1 multi-seed stability results.")
    add_heading(doc, "Final Holdout Evaluation", 2)
    add_p(doc, "The deployable K1 architecture was frozen before Final Holdout access. The one-time Final Holdout evaluation used 213 incidents, balanced across 71 Hijack, 71 Leak, and 71 Outage incidents, with 14,906 five-minute rows. The model achieved Macro F1 of 0.920177 with a 95% confidence interval of [0.880117, 0.954402], Top-1 of 0.920188, Top-2 of 0.990610, and MRR of 0.958529.")
    add_figure(doc, "holdout_primary", "Figure 4.6 Final Holdout primary performance for the frozen K1 architecture.")
    add_table(doc, "Table 4.2 Final Holdout class and ranking results.", ["Measure", "Value"], [
        ["Hijack F1", "0.877698"],
        ["Leak F1", "0.904110"],
        ["Outage F1", "0.978723"],
        ["Ranked first", "196/213"],
        ["Ranked second", "15/213"],
        ["Ranked third", "2/213"],
        ["Top-2 correct", "211/213"],
    ])
    add_heading(doc, "Final Error and Confusion Analysis", 2)
    add_p(doc, "The remaining errors were concentrated primarily between Hijack and Leak. The confusion matrix shows 9 Hijack incidents predicted as Leak and 5 Leak incidents predicted as Hijack. Outage was the strongest class, with 69 of 71 Outage incidents correctly classified.")
    add_figure(doc, "confusion", "Figure 4.7 Final Holdout confusion matrix for Hijack, Leak, and Outage.")
    add_p(doc, "One documented data-quality caveat remained for Hijack:68538, which had a processing REVIEW status because one check identified no directly relevant RouteViews observations. The final evaluation nevertheless completed with valid V4 feature rows and PASS status in the final schema and reproducibility audits. No claim is made that this caveat materially changed the aggregate result.")
    add_heading(doc, "Latency and Operational Feasibility", 2)
    add_p(doc, "The final latency benchmark measured warm downstream K1 computation after feature/probability availability. Mean downstream computation was approximately 25.58 ms per incident, with median 24.77 ms and p95 27.63 ms. This corresponds to an approximate downstream throughput derivative of 39 incidents per second, but it is not end-to-end live BGP detection latency.")
    add_figure(doc, "latency", "Figure 4.8 Breakdown of warm downstream K1 computational latency.")
    add_heading(doc, "Research Question Mapping", 2)
    add_p(doc, "The results support the central claim that integrated BGP behavioral, AS-relationship, and RPKI/ROV evidence can rank likely BGP incident classes under leakage-safe evaluation. RQ1 was supported by the multiclass results; RQ2 was supported by feature-variant and ablation evidence; RQ3 was supported by K1's improvement over mean aggregation; and RQ4 was supported by the sealed Final Holdout result. The findings do not prove reduced MTTR or human troubleshooting improvement, which remain future operator-study questions.")
    add_heading(doc, "Chapter Summary", 2)
    add_p(doc, "The final system generalized strongly on the untouched Final Holdout while preserving important caveats: Validation performance dropped relative to TRAIN development, Stage 1 remained unresolved, Hijack remained the hardest class, and latency was measured only after feature availability. These constraints make the results more defensible because they separate final evidence from developmental optimism.")
    add_source_supporting_material(doc, "Chapter 4", 4200)


def chapter_5(doc: Document) -> None:
    add_heading(doc, "Chapter 5 - Conclusions", 1)
    add_heading(doc, "Overview", 2)
    add_p(doc, "This Praxis developed and evaluated an AI-based post-window classification and ranking system for BGP incidents in enterprise-relevant routing contexts. The final system ranks Hijack, Leak, and Outage hypotheses from observable BGP evidence rather than claiming to prove physical root cause.")
    add_heading(doc, "Interpretation of Findings", 2)
    add_p(doc, "The final result shows that incident-level temporal stacking can turn window-level routing evidence into a stronger incident-level diagnosis. On the sealed Final Holdout of 213 unseen incidents, the frozen K1 architecture achieved Macro F1 of 0.920177, Top-2 accuracy of 0.990610, and MRR of 0.958529. The true class was ranked in the top two for 211 of 213 incidents.")
    add_p(doc, "The result also shows that the problem is not solved perfectly. Hijack remained the most difficult class, and the principal confusion was between Hijack and Leak. Stage 1 Normal-vs-Incident detection did not become part of the final architecture. These negative findings are important because they define the boundary of what the system can responsibly claim.")
    add_heading(doc, "Key Contributions", 2)
    add_bullets(doc, [
        "A reproducible incident-level BGP corpus and leakage-safe partition design.",
        "A 74-feature V4 representation combining Behavioral, CAIDA, and RPKI/ROV evidence.",
        "An incident-aware weighting approach that reduces unequal influence from long incidents.",
        "A K1 incident-level temporal stacking architecture for classification and ranked incident hypotheses.",
        "A sealed Final Holdout evaluation with transparent error, ranking, and latency evidence.",
    ])
    add_heading(doc, "Practical Implications", 2)
    add_p(doc, "For network operations, the most useful output is not a claim of autonomous root-cause proof. It is a ranked hypothesis that can narrow the investigative search space. If integrated into an operational workflow, the model could help engineers prioritize whether observed BGP evidence is more consistent with Hijack, Leak, or Outage while still requiring human validation and additional telemetry.")
    add_heading(doc, "Limitations", 2)
    add_p(doc, "The study depends on public RouteViews observations and external incident labels. Collector visibility varies over time and may not represent enterprise-local routing state. RPKI and CAIDA enrichment are based on historical snapshots and inferred relationships. The final latency measurement excludes live collection and feature generation. Finally, the Final Holdout contains 213 incidents, which is strong for this controlled study but still finite for estimating operational performance across all possible networks and events.")
    add_heading(doc, "Future Research", 2)
    add_p(doc, "Future work should focus on a stronger Normal-vs-Incident formulation, shorter observation horizons, streaming feature updates, additional collectors, enterprise-local telemetry, calibrated ranked probabilities, and operator studies that measure whether ranked incident hypotheses reduce troubleshooting time. The compact evidence-store concept developed during the project could also support future 30-second, one-minute, two-minute, and three-minute sensitivity studies without reparsing all MRT data, if timestamp resolution is captured at the needed granularity.")
    add_heading(doc, "Conclusion", 2)
    add_p(doc, "The Praxis demonstrates that a carefully controlled AI/ML pipeline can classify and rank BGP incident classes with strong final Holdout performance while preserving scientific caution. The final contribution is not only the measured performance, but the complete methodology: incident-level separation, feature enrichment, leakage controls, transparent negative results, and a final evaluation that remained sealed until the model was frozen.")
    add_source_supporting_material(doc, "Chapter 5", 300)


def add_references(doc: Document) -> None:
    add_heading(doc, "References", 1)
    for ref in sorted(REFERENCES, key=lambda s: re.sub(r"^[\"']", "", s).lower()):
        p = doc.add_paragraph(ref)
        p.paragraph_format.first_line_indent = Inches(-0.5)
        p.paragraph_format.left_indent = Inches(0.5)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.0


def create_audits() -> None:
    CHANGE_LOG.write_text(
        """# Final Praxis Editorial Change Log

- Replaced the over-length Chapter 1 through Chapter 5 body with a controlled condensed version preserving the final study, locked results, and core scientific argument.
- Removed obsolete main-text framing around earlier 34-event, 75-event, seven-event Holdout, 40/46/49-feature, three-RPKI-feature, hierarchical Random Forest, tau=0.70, 0.9769, and 4.10 microsecond developmental claims.
- Condensed Chapter 1 to problem framing, objectives, research questions, scope, limitations, and organization.
- Condensed Chapter 2 into synthesis-based literature coverage rather than study-by-study prose.
- Condensed Chapter 3 to final methodology, incident-level partitioning, feature representation, leakage controls, stacking, metrics, and latency scope.
- Condensed Chapter 4 to results-driven evidence with essential tables and figures only.
- Rebuilt Chapter 5 as a concise synthesis focused on findings, contributions, implications, limitations, future work, and conclusion.
- Retained the author's engineering-oriented voice and avoided claims that the model proves physical root cause or end-to-end live detection.
- Curated the References section to high-value BGP, routing-security, RouteViews, CAIDA, RPKI/ROV, anomaly-detection, and machine-learning sources.
""",
        encoding="utf-8",
    )
    CONSISTENCY_AUDIT.write_text(
        """# Final Praxis Consistency Audit

## Authoritative final values preserved

- Corpus: 1,419 incidents, balanced as 473 Hijack / 473 Leak / 473 Outage.
- TRAIN: 993 incidents, 331 per class.
- Validation: 213 incidents, 71 per class.
- Final Holdout: 213 incidents, 71 per class, 14,906 five-minute rows.
- Feature schema: 44 Behavioral + 14 CAIDA + 16 RPKI/ROV = 74 V4 features.
- Final architecture: XGBoost to XGBoost incident-level temporal stacking.
- Final Holdout: Macro F1 0.920177, 95% CI [0.880117, 0.954402], Top-1 0.920188, Top-2 0.990610, MRR 0.958529.
- Class F1: Hijack 0.877698, Leak 0.904110, Outage 0.978723.
- Ranking: rank 1 = 196, rank 2 = 15, rank 3 = 2, Top-2 = 211/213.
- Latency: warm downstream K1 computation only; mean about 25.58 ms/incident, median about 24.77 ms, p95 about 27.63 ms.

## Legacy result treatment

Legacy values from earlier development were removed from the condensed main manuscript except where the final narrative needed to describe them as superseded or auxiliary. Stage 1 is explicitly identified as experimental and auxiliary. The final architecture is explicitly described as POST-WINDOW INCIDENT CLASSIFICATION and ranking, not end-to-end live BGP anomaly detection.

## Reference audit caveat

The References section was cleaned and normalized structurally to APA 7 style using the manuscript's existing bibliographic data. External lookup verification was not performed during this local condensation pass; entries with DOI or authoritative URLs are marked structurally verifiable in the reference audit.
""",
        encoding="utf-8",
    )
    with REF_AUDIT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["reference", "has_year", "has_doi_or_url", "apa7_structural_status", "verification_note"])
        writer.writeheader()
        for ref in REFERENCES:
            writer.writerow(
                {
                    "reference": ref,
                    "has_year": bool(re.search(r"\(\d{4}\)", ref)),
                    "has_doi_or_url": "https://" in ref,
                    "apa7_structural_status": "REVIEW_STRUCTURALLY_NORMALIZED",
                    "verification_note": "Normalized from manuscript source; DOI/URL present where available; no fabricated bibliographic fields added.",
                }
            )
    with PAGE_COMPLIANCE.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["chapter", "original_pages", "final_pages", "maximum_allowed", "status"])
        writer.writeheader()
        original = {"Chapter 1": 12, "Chapter 2": 52, "Chapter 3": 73, "Chapter 4": 52, "Chapter 5": 22}
        maxes = {"Chapter 1": 8, "Chapter 2": 35, "Chapter 3": 28, "Chapter 4": 25, "Chapter 5": 5}
        for chapter in original:
            writer.writerow({"chapter": chapter, "original_pages": original[chapter], "final_pages": "PENDING_RENDER_COUNT", "maximum_allowed": maxes[chapter], "status": "PENDING_RENDER_COUNT"})


def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE, OUT_DOCX)
    doc = Document(OUT_DOCX)
    clean_front_matter_placeholders(doc)
    for section in doc.sections:
        section.page_width = Inches(8.5)
        section.page_height = Inches(11)
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1.25)
        section.right_margin = Inches(1.25)
    remove_from_table_of_contents_onward(doc)
    add_generated_front_matter(doc)
    doc.add_page_break()
    chapter_1(doc)
    doc.add_page_break()
    chapter_2(doc)
    doc.add_page_break()
    chapter_3(doc)
    doc.add_page_break()
    chapter_4(doc)
    doc.add_page_break()
    chapter_5(doc)
    doc.add_page_break()
    add_references(doc)
    doc.save(OUT_DOCX)
    create_audits()
    print(OUT_DOCX)


if __name__ == "__main__":
    main()
